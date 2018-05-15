import asyncio
import base64
import logging
from . import crypto
from . import errors
from . import eventing
from . import hub
from . import protobufs
from . import queue_async
from . import storage
from .websocket_resource import WebSocketResource


logger = logging.getLogger(__name__)
ENV_TYPES = dict(protobufs.Envelope.Type.items())
DATA_FLAGS = dict(protobufs.DataMessage.Flags.items())


class MessageReceiver(eventing.EventTarget):

    def __init__(self, signal, addr, device_id, signaling_key, no_web_socket=False):
        self.signal = signal
        self.addr = addr
        self.device_id = device_id
        self.signaling_key = signaling_key
        if not no_web_socket:
            url = self.signal.get_message_websocket_url()
            self.wsr = WebSocketResource(url, {
                "handleRequest": lambda request: queue_async(self, self.handle_request),
                "keepalive": {
                    "path": '/v1/keepalive',
                    "disconnect": True
                }
            })
            self.wsr.addEventListener('close', self.on_socket_close.bind(self))
            self.wsr.addEventListener('error', self.on_socket_error.bind(self))

    @classmethod
    async def factory(cls, no_web_socket):
        signal = await hub.SignalClient.factory()
        addr = await storage.get_state('addr')
        device_id = await storage.get_state('device_id')
        signaling_key = await storage.get_state('signaling_key')
        return cls(signal, addr, device_id, signaling_key, no_web_socket)

    async def check_registration(self):
        try:
            # possible auth or network issue. Make a request to confirm
            await self.signal.get_devices()
        except Exception as e:
            logger.exception("Invalid network state")
            ev = eventing.Event('error')
            ev.error = e
            await self.dispatch_event(ev)

    async def connect(self):
        if self._closing:
            raise Exception("Invalid State: Already Closed")
        if self._connecting:
            logger.warn("Duplicate connect detected")
        else:
            async def _connect():
                attempts = 0
                while not self._closing:
                    try:
                        await self.wsr.connect()
                        if attempts:
                            logger.info("Reconnected websocket")
                        return
                    except Exception as e:
                        await self.check_registration()
                        logger.warn(f'Connect problem ({attempts} attempts)')
                    attempts += 1
            self._connecting = _connect()
        await self._connecting
        self._connecting = None

    def close(self):
        self._closing = True
        self.wsr.close()

    async def drain(self):
        """ Pop messages directly from the messages API until it's empty. """
        if self.wsr:
            raise TypeError("Fetch is invalid when websocket is in use")
        more = True
        while more:
            data = await self.signal.request(call='messages')
            more = data['more']
            deleting = []
            for envelope in data['messages']:
                if envelope.content:
                    envelope.content = base64.b64decode(envelope.content)
                if envelope.message:
                    envelope.legacyMessage = base64.b64decode(envelope.message)
                await self.handle_envelope(envelope)
                deleting.append(self.signal.request(call='messages',
                    method='DELETE',
                    urn=f'/{envelope.source}/{envelope.timestamp}'))
            await asyncio.gather(deleting)

    def on_socket_error(self, ev):
        logger.warn('Message Receiver WebSocket error:', ev)

    async def on_socket_close(self, ev):
        if self._closing:
            return
        logger.warn('Websocket closed:', ev.code, ev.reason or '')
        await self.check_registration()
        if not self._closing:
            await self.connect()

    async def handle_request(self, request):
        if request.path == '/api/v1/queue/empty':
            logger.debug("WebSocket queue empty")
            request.respond(200, 'OK')
            return
        elif request.path != '/api/v1/message' or request.verb != 'PUT':
            logger.error("Expected PUT /message instead of:", request)
            request.respond(400, 'Invalid Resource')
            raise Exception('Invalid WebSocket resource received')
        envelope = None
        try:
            data = crypto.decrypt_websocket_message(request.body,
                                                    self.signaling_key)
            envelope = protobufs.Envelope.toObject(protobufs.Envelope.decode(data))
            envelope.timestamp = envelope.timestamp.toNumber()
        except Exception as e:
            logger.error("Error handling incoming message:", e)
            request.respond(500, 'Bad encrypted websocket message')
            ev = eventing.Event('error')
            ev.error = e
            await self.dispatch_event(ev)
            raise e
        try:
            await self.handle_envelope(envelope)
        finally:
            request.respond(200, 'OK')

    async def handle_envelope(self, envelope, reentrant=True):
        handler = None
        if envelope.type == ENV_TYPES['RECEIPT']:
            handler = self.handle_delivery_receipt
        elif envelope.content:
            handler = self.handle_content_message
        elif envelope.legacyMessage:
            handler = self.handle_legacy_message
        else:
            raise Exception('Received message with no content and no legacyMessage')
        try:
            await handler.call(self, envelope)
        except errors.MessageCounterError:  #  XXX Where who do dem?
            logger.warn("Ignoring MessageCounterError for:", envelope)
            return
        except errors.IncomingIdentityKeyError:
            if reentrant:
                raise
            await self.dispatch_event(eventing.KeyChangeEvent(e))
            if e.accepted:
                envelope.keyChange = True
                return await self.handle_envelope(envelope, reentrant=True)
        except errors.RelayError as e:
            logger.warn("Supressing RelayError:", e)
        except Exception as e:
            ev = eventing.Event('error')
            ev.error = e
            ev.proto = envelope
            await self.dispatch_event(ev)
            raise

    async def handle_delivery_receipt(self, envelope):
        ev = eventing.Event('receipt')
        ev.proto = envelope
        await self.dispatch_event(ev)

    def unpad(self, buf):
        for i in range(len(buf) - 1, -1, -1):
            if buf[i] == 0x80:
                return buf[:i]
            elif buf[i] != 0x00:
                raise ValueError('Invalid padding')
        return buf # empty

    async def decrypt(self, envelope, ciphertext):
        addr = libsignal.SignalProtocolAddress(envelope.source,
                                                         envelope.sourceDevice)
        sessionCipher = libsignal.SessionCipher(storage, addr)
        if envelope.type == ENV_TYPES['CIPHERTEXT']:
            return self.unpad(await sessionCipher.decryptWhisperMessage(ciphertext))
        elif envelope.type == ENV_TYPES['PREKEY_BUNDLE']:
            return await self.decryptPreKeyWhisperMessage(ciphertext, sessionCipher, addr)
        raise Exception("Unknown message type")

    async def decryptPreKeyWhisperMessage(self, ciphertext, sessionCipher, address):
        try:
            return self.unpad(await sessionCipher.decryptPreKeyWhisperMessage(ciphertext))
        except Exception as e:
            # XXX port
            import pdb;pdb.set_trace()
            if e.message == 'Unknown identity key':
                raise errors.IncomingIdentityKeyError(address, ciphertext,
                                                      e.identitykey)
            raise e

    async def handle_sent_message(self, sent, envelope):
        if sent.message.flags & DATA_FLAGS['END_SESSION']:
            await self.handle_end_session(sent.destination)
        await self.process_decrypted(sent.message, self.addr)
        ev = eventing.Event('sent')
        ev.data = {
            source: envelope.source,
            sourceDevice: envelope.sourceDevice,
            timestamp: sent.timestamp.toNumber(),
            destination: sent.destination,
            message: sent.message
        }
        if sent.expirationStartTimestamp:
          ev.data.expirationStartTimestamp = sent.expirationStartTimestamp.toNumber()
        await self.dispatch_event(ev)

    async def handle_data_message(self, message, envelope, content):
        if message.flags & DATA_FLAGS['END_SESSION']:
            await self.handle_end_session(envelope.source)
        await self.process_decrypted(message, envelope.source)
        ev = eventing.Event('message')
        ev.data = {
            "timestamp": envelope.timestamp,
            "source": envelope.source,
            "sourceDevice": envelope.sourceDevice,
            "message": message,
            "keyChange": envelope.keyChange
        }
        await self.dispatch_event(ev)

    async def handle_legacy_message(self, envelope):
        data = await self.decrypt(envelope, envelope.legacyMessage)
        messageProto = protobufs.DataMessage.decode(data)
        message = protobufs.DataMessage.toObject(messageProto)
        await self.handle_data_message(message, envelope)

    async def handle_content_message(self, envelope):
        data = await self.decrypt(envelope, envelope.content)
        contentProto = protobufs.Content.decode(data)
        content = protobufs.Content.toObject(contentProto)
        if content.syncMessage:
            await self.handle_sync_message(content.syncMessage, envelope, content)
        elif content.dataMessage:
            await self.handle_data_message(content.dataMessage, envelope, content)
        else:
            raise TypeError('Got content message with no dataMessage or syncMessage')

    async def handle_sync_message(self, message, envelope, content):
        if envelope.source != self.addr:
            raise ReferenceError('Received sync message from another addr')
        if envelope.sourceDevice == self.device_id:
            raise ReferenceError('Received sync message from our own device')
        if message.sent:
            await self.handle_sent_message(message.sent, envelope)
        elif message.read:
            await self.handle_read(message.read, envelope)
        elif message.contacts:
            logger.error("Deprecated contact sync message:", message, envelope, content)
            raise TypeError('Deprecated contact sync message')
        elif message.groups:
            logger.error("Deprecated group sync message:", message, envelope, content)
            raise TypeError('Deprecated group sync message')
        elif message.blocked:
            self.handle_blocked(message.blocked, envelope)
        elif message.request:
            logger.error("Deprecated group request sync message:", message, envelope, content)
            raise TypeError('Deprecated group request sync message')
        else:
            logger.error("Empty sync message:", message, envelope, content)
            raise TypeError('Empty SyncMessage')

    async def handle_read(self, read, envelope):
        for x in read:
            ev = eventing.Event('read')
            ev.timestamp = envelope.timestamp
            ev.read = {
                "timestamp": x.timestamp.toNumber(),
                "sender": x.sender,
                "source": envelope.source,
                "sourceDevice": envelope.sourceDevice
            }
            await self.dispatch_event(ev)

    def handle_blocked(self, blocked):
        raise Exception("UNSUPPORTRED")

    async def handle_attachment(self, attachment):
        encrypted = await self.signal.get_attachment(attachment.id)
        attachment.data = await crypto.decrypt_attachment(encrypted,
                                                          attachment.key)

    async def handle_end_session(self, addr):
        device_ids = await storage.get_device_ids(addr)
        jobs = []
        for device_id in device_ids:
            address = libsignal.SignalProtocolAddress(addr, device_id)
            sessionCipher = libsignal.SessionCipher(storage, address)
            logger.warn('Closing session for', addr, device_id)
            sessionCipher.closeOpenSessionForDevice()

    async def process_decrypted(self, msg, source):
        """ Now that its decrypted, validate the message and clean it up for
        consumer processing.  Note that messages may (generally) only perform
        one action and we ignore remaining fields after the first action. """
        import pdb;pdb.set_trace() # validate what probotufs on python look like.
        if msg.flags is None:
            msg.flags = 0
        if msg.expireTimer is None:
            msg.expireTimer = 0
        if msg.flags & DATA_FLAGS['END_SESSION']:
            return msg
        if msg.group:
            # We should blow up here very soon. XXX
            logger.error("Legacy group message detected", msg)
        if msg.attachments:
            await asyncio.gather(map(self.handle_attachment, msg.attachments))
        return msg
