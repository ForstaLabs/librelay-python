import asyncio
import base64
import logging
from . import crypto
from . import errors
from . import eventing
from . import hub
from . import protobufs
from . import storage
from .websocket_resource import WebSocketResource


store = storage.getStore()
logger = logging.getLogger(__name__)


class MessageReceiver(eventing.EventTarget):

    def __init__(self, signal, addr, device_id, signaling_key, no_web_socket=False):
        self._closing = False
        self._closed = asyncio.Future()
        self._connecting = None
        self.signal = signal
        self.addr = addr
        self.device_id = device_id
        self.signaling_key = signaling_key
        if not no_web_socket:
            url = self.signal.getMessageWebSocketUrl()
            self.wsr = WebSocketResource(url, handleRequest=self.handleRequest)

    @classmethod
    async def factory(cls, no_web_socket=False):
        signal = await hub.SignalClient.factory()
        addr = await store.getState('addr')
        device_id = await store.getState('deviceId')
        signaling_key = await store.getState('signalingKey')
        return cls(signal, addr, device_id, signaling_key, no_web_socket)

    async def checkRegistration(self):
        try:
            # possible auth or network issue. Make a request to confirm
            await self.signal.getDevices()
        except Exception as e:
            logger.exception("Invalid network state")
            ev = eventing.Event('error')
            ev.error = e
            await self.dispatchEvent(ev)

    async def connect(self):
        if self._closing:
            raise RuntimeError("Invalid State: Already Closed")
        if self._connecting:
            logger.warning("Duplicate connect detected")
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
                        await self.checkRegistration()
                        logger.exception('CONNECT ERROR')  # XXX 
                        logger.warning(f'Connect problem ({attempts} attempts)')
                    attempts += 1
            self._connecting = _connect()
        await self._connecting
        self._connecting = None

    async def close(self):
        try:
            self._closing = True
            wsr = self.wsr
            self.wsr = None
            await wsr.close()
        finally:
            self._closed.set_result(None)

    async def closed(self):
        """ Block until we are manually closed. """
        await self._closed

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
                await self.handleEnvelope(envelope)
                deleting.append(self.signal.request(call='messages',
                    method='DELETE',
                    urn=f'/{envelope.source}/{envelope.timestamp}'))
            await asyncio.gather(deleting)

    def onSocketError(self, ev):
        # XXX wire in without callback
        logger.warning('Message Receiver WebSocket error:', ev)

    async def onSocketClose(self, ev):
        # XXX wire in without callback
        if self._closing:
            return
        logger.warning('Websocket closed:', ev.code, ev.reason or '')
        await self.checkRegistration()
        if not self._closing:
            await self.connect()

    async def handleRequest(self, request):
        if request.path == '/api/v1/queue/empty':
            logger.debug("WebSocket queue empty")
            await request.respond(200, 'OK')
            return
        elif request.path != '/api/v1/message' or request.verb != 'PUT':
            logger.error("Expected PUT /message instead of:", request)
            await request.respond(400, 'Invalid Resource')
            raise Exception('Invalid WebSocket resource received')
        envelope = None
        try:
            data = crypto.decryptWebSocketMessage(request.body, self.signaling_key)
            envelope = protobufs.Envelope()
            envelope.ParseFromString(data)
        except Exception as e:
            logger.exception("Error handling incoming message")
            await request.respond(500, 'Bad encrypted websocket message')
            ev = eventing.Event('error')
            ev.error = e
            await self.dispatchEvent(ev)
            raise e
        try:
            await self.handleEnvelope(envelope)
        finally:
            await request.respond(200, 'OK')

    async def handleEnvelope(self, envelope, reentrant=True):
        handler = None
        if envelope.type == envelope.RECEIPT:
            handler = self.handleDeliveryReceipt
        elif envelope.content:
            handler = self.handleContentMessage
        elif envelope.legacyMessage:
            handler = self.handleLegacyMessage
        else:
            raise Exception('Received message with no content and no legacyMessage')
        try:
            await handler.call(self, envelope)
        #except errors.MessageCounterError:  #  XXX Where who do dem?
        #    logger.warning("Ignoring MessageCounterError for:", envelope)
        #    return
        except errors.IncomingIdentityKeyError as e:
            if reentrant:
                raise
            await self.dispatchEvent(eventing.KeyChangeEvent(e))
            if e.accepted:
                envelope.keyChange = True
                return await self.handleEnvelope(envelope, reentrant=True)
        except errors.RelayError as e:
            logger.warning("Supressing RelayError:", e)
        except Exception as e:
            ev = eventing.Event('error')
            ev.error = e
            ev.proto = envelope
            await self.dispatchEvent(ev)
            raise

    async def handleDeliveryReceipt(self, envelope):
        ev = eventing.Event('receipt')
        ev.proto = envelope
        await self.dispatchEvent(ev)

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
        sessionCipher = libsignal.SessionCipher(store, addr)
        if envelope.type == envelope.CIPHERTEXT:
            return self.unpad(await sessionCipher.decryptWhisperMessage(ciphertext))
        elif envelope.type == envelope.PREKEY_BUNDLE:
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

    async def handleSentMessage(self, sent, envelope):
        if sent.message.flags & sent.message.END_SESSION:
            await self.handleEndSession(sent.destination)
        await self.processDecrypted(sent.message, self.addr)
        ev = eventing.Event('sent')
        ev.data = {
            "source": envelope.source,
            "sourceDevice": envelope.sourceDevice,
            "timestamp": sent.timestamp,
            "destination": sent.destination,
            "message": sent.message
        }
        if sent.expirationStartTimestamp:
          ev.data.expirationStartTimestamp = sent.expirationStartTimestamp
        await self.dispatchEvent(ev)

    async def handleDataMessage(self, message, envelope, content):
        if message.flags & message.END_SESSION:
            await self.handleEndSession(envelope.source)
        await self.processDecrypted(message, envelope.source)
        ev = eventing.Event('message')
        ev.data = {
            "timestamp": envelope.timestamp,
            "source": envelope.source,
            "sourceDevice": envelope.sourceDevice,
            "message": message,
            "keyChange": envelope.keyChange
        }
        await self.dispatchEvent(ev)

    async def handleLegacyMessage(self, envelope):
        data = await self.decrypt(envelope, envelope.legacyMessage)
        message = protobufs.DataMessage()
        message.ParseFromString(data)
        await self.handleDataMessage(message, envelope)

    async def handleContentMessage(self, envelope):
        data = await self.decrypt(envelope, envelope.content)
        content = protobufs.Content()
        content.ParseFromString(data)
        if content.syncMessage:
            await self.handleSyncMessage(content.syncMessage, envelope, content)
        elif content.dataMessage:
            await self.handleDataMessage(content.dataMessage, envelope, content)
        else:
            raise TypeError('Got content message with no dataMessage or syncMessage')

    async def handleSyncMessage(self, message, envelope, content):
        if envelope.source != self.addr:
            raise ReferenceError('Received sync message from another addr')
        if envelope.sourceDevice == self.device_id:
            raise ReferenceError('Received sync message from our own device')
        if message.sent:
            await self.handleSentMessage(message.sent, envelope)
        elif message.read:
            await self.handleRead(message.read, envelope)
        elif message.contacts:
            logger.error("Deprecated contact sync message:", message, envelope, content)
            raise TypeError('Deprecated contact sync message')
        elif message.groups:
            logger.error("Deprecated group sync message:", message, envelope, content)
            raise TypeError('Deprecated group sync message')
        elif message.blocked:
            self.handleBlocked(message.blocked, envelope)
        elif message.request:
            logger.error("Deprecated group request sync message:", message, envelope, content)
            raise TypeError('Deprecated group request sync message')
        else:
            logger.error("Empty sync message:", message, envelope, content)
            raise TypeError('Empty SyncMessage')

    async def handleRead(self, read, envelope):
        for x in read:
            ev = eventing.Event('read')
            ev.timestamp = envelope.timestamp
            ev.read = {
                "timestamp": x.timestamp,
                "sender": x.sender,
                "source": envelope.source,
                "sourceDevice": envelope.sourceDevice
            }
            await self.dispatchEvent(ev)

    def handleBlocked(self, blocked):
        raise Exception("UNSUPPORTRED")

    async def handleAttachment(self, attachment):
        encrypted = await self.signal.getAttachment(attachment.id)
        attachment.data = await crypto.decryptAttachment(encrypted,
                                                          attachment.key)

    async def handleEndSession(self, addr):
        device_ids = await store.getDeviceIds(addr)
        jobs = []
        for device_id in device_ids:
            address = libsignal.SignalProtocolAddress(addr, device_id)
            sessionCipher = libsignal.SessionCipher(store, address)
            logger.warning('Closing session for', addr, device_id)
            sessionCipher.closeOpenSessionForDevice()

    async def processDecrypted(self, msg, source):
        """ Now that its decrypted, validate the message and clean it up for
        consumer processing.  Note that messages may (generally) only perform
        one action and we ignore remaining fields after the first action. """
        import pdb;pdb.set_trace() # validate what probotufs on python look like.
        if msg.flags is None:
            msg.flags = 0
        if msg.expireTimer is None:
            msg.expireTimer = 0
        if msg.flags & msg.END_SESSION:
            return msg
        if msg.group:
            # We should blow up here very soon. XXX
            logger.error("Legacy group message detected", msg)
        if msg.attachments:
            await asyncio.gather(map(self.handleAttachment, msg.attachments))
        return msg
