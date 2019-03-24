import asyncio
import base64
import logging
from . import crypto
from . import errors
from . import eventing
from . import exchange
from . import hub
from . import message_sender
from . import protobufs
from . import storage
from .websocket_resource import WebSocketResource
from libsignal.duplicatemessagexception import DuplicateMessageException
from libsignal.protocol.prekeywhispermessage import PreKeyWhisperMessage
from libsignal.protocol.whispermessage import WhisperMessage
from libsignal.sessioncipher import SessionCipher
from libsignal.untrustedidentityexception import UntrustedIdentityException


store = storage.getStore()
logger = logging.getLogger(__name__)


class MessageReceiver(eventing.EventTarget):

    def __init__(self, signal, atlas, addr, device_id, signaling_key, no_web_socket=False):
        assert isinstance(signal, hub.SignalClient)
        assert isinstance(atlas, hub.AtlasClient)
        assert isinstance(addr, str)
        assert isinstance(device_id, int)
        self._closing = False
        self._closed = asyncio.Future()
        self._connecting = None
        self._sender = message_sender.MessageSender(addr, signal, atlas)
        self.signal = signal
        self.atlas = atlas
        self.addr = addr
        self.device_id = device_id
        self.signaling_key = signaling_key
        if not no_web_socket:
            url = self.signal.getMessageWebSocketUrl()
            self.wsr = WebSocketResource(url, handleRequest=self.handleRequest)
            self.wsr.addEventListener('close', self.onSocketClose)
            self.wsr.addEventListener('error', self.onSocketError)

    @classmethod
    def factory(cls, no_web_socket=False):
        signal = hub.SignalClient.factory()
        atlas = hub.AtlasClient.factory()
        addr = store.getState('addr')
        device_id = store.getState('deviceId')
        signaling_key = store.getState('signalingKey')
        return cls(signal, atlas, addr, device_id, signaling_key, no_web_socket)

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
                        await self.checkRegistration()
                        logger.exception('CONNECT ERROR')  # XXX 
                        logger.warn(f'Connect problem ({attempts} attempts)')
                    attempts += 1
            self._connecting = _connect()
        await self._connecting
        self._connecting = None

    async def close(self):
        self._closing = True
        wsr = self.wsr
        self.wsr = None
        try:
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
        logger.warn('Message Receiver WebSocket error: %s' % (ev,))

    async def onSocketClose(self, ev):
        if self._closing:
            return
        logger.warn(f'Websocket closed: {ev.code} {ev.reason}')
        await self.checkRegistration()
        if not self._closing:
            await self.connect()

    async def handleRequest(self, request):
        if request.path == '/api/v1/queue/empty':
            logger.debug("WebSocket queue empty")
            await request.respond(200, 'OK')
            return
        elif request.path != '/api/v1/message' or request.verb != 'PUT':
            logger.error("Expected PUT /message instead of: %s" % request)
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

    async def handleEnvelope(self, envelope, keychange=False):
        handler = None
        if envelope.type == envelope.RECEIPT:
            handler = self.handleDeliveryReceipt
        elif envelope.HasField('content'):
            handler = self.handleContentMessage
        elif envelope.HasField('legacyMessage'):
            handler = self.handleLegacyMessage
        else:
            raise Exception('Received message with no content and no legacyMessage')
        try:
            await handler(envelope, keychange)
        except DuplicateMessageException:
            logger.warn("Ignoring duplicate message for: %s" % (envelope,))
            return
        except UntrustedIdentityException as e:
            if keychange:
                logger.exception("Multiple identity exceptions for a single message")
                raise
            keyChangeEvent = eventing.KeyChangeEvent(e)
            await self.dispatchEvent(keyChangeEvent)
            if keyChangeEvent.accepted:
                return await self.handleEnvelope(envelope, keychange=True)
        except errors.RelayError as e:
            logger.warn("Supressing RelayError: %s" % (e,))
        except Exception as e:
            ev = eventing.Event('error')
            ev.error = e
            ev.proto = envelope
            await self.dispatchEvent(ev)
            raise
        # XXX Port SessionError handling for closesession

    async def handleDeliveryReceipt(self, envelope, keychange):
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

    def decrypt(self, envelope, ciphertext):
        stores = [store] * 4
        sessionCipher = SessionCipher(*stores, envelope.source,
                                      envelope.sourceDevice)
        if envelope.type == envelope.CIPHERTEXT:
            msg = WhisperMessage(serialized=ciphertext)
            plainBuf = sessionCipher.decryptMsg(msg)
        elif envelope.type == envelope.PREKEY_BUNDLE:
            msg = PreKeyWhisperMessage(serialized=ciphertext)
            plainBuf = sessionCipher.decryptPkmsg(msg)
        else:
            raise TypeError("Unknown message type")
        return self.unpad(plainBuf)

    async def handleSentMessage(self, sent, envelope):
        if sent.message.flags & sent.message.END_SESSION:
            logger.error("Unsupported syncMessage end-session sent by "
                         "device: %d", envelope.sourceDevice)
            return
        ex = exchange.decode(sent.message, messageSender=self._sender,
                             messageReceiver=self, atlas=self.atlas,
                             signal=self.signal)
        ex.setSource(envelope.source);
        ex.setSourceDevice(envelope.sourceDevice);
        ex.setTimestamp(sent.timestamp);
        ex.setAge(envelope.age);
        ev = eventing.Event('sent')
        ev.data = {
            "source": envelope.source,
            "sourceDevice": envelope.sourceDevice,
            "timestamp": sent.timestamp,
            "destination": sent.destination,
            "message": sent.message,
            "exchange": ex,
            "age": envelope.age
        }
        if sent.expirationStartTimestamp:
          ev.data.expirationStartTimestamp = sent.expirationStartTimestamp
        await self.dispatchEvent(ev)

    async def handleDataMessage(self, message, envelope, keychange):
        if message.flags & message.END_SESSION:
            await self.handleEndSession(envelope.source)
        ex = exchange.decode(message, messageSender=self._sender,
                             messageReceiver=self, atlas=self.atlas,
                             signal=self.signal)
        ex.setSource(envelope.source);
        ex.setSourceDevice(envelope.sourceDevice);
        ex.setTimestamp(envelope.timestamp);
        ex.setAge(envelope.age);
        ev = eventing.Event('message')
        ev.data = {
            "timestamp": envelope.timestamp,
            "source": envelope.source,
            "sourceDevice": envelope.sourceDevice,
            "message": message,
            "exchange": ex,
            "keyChange": keychange,
            "age": envelope.age
        }
        await self.dispatchEvent(ev)

    async def handleLegacyMessage(self, envelope, keychange):
        data = self.decrypt(envelope, envelope.legacyMessage)
        message = protobufs.DataMessage()
        message.ParseFromString(data)
        await self.handleDataMessage(message, envelope, keychange)

    async def handleContentMessage(self, envelope, keychange):
        data = self.decrypt(envelope, envelope.content)
        content = protobufs.Content()
        content.ParseFromString(data)
        if content.HasField('syncMessage'):
            await self.handleSyncMessage(content.syncMessage, envelope)
        elif content.HasField('dataMessage'):
            await self.handleDataMessage(content.dataMessage, envelope,
                                         keychange)
        else:
            raise TypeError('Got content message with no dataMessage or syncMessage')

    async def handleSyncMessage(self, message, envelope):
        if envelope.source != self.addr:
            raise ReferenceError('Received sync message from another addr')
        if envelope.sourceDevice == self.device_id:
            raise ReferenceError('Received sync message from our own device')
        if message.HasField('sent'):
            await self.handleSentMessage(message.sent, envelope)
        elif message.read:
            await self.handleRead(message.read, envelope)
        elif message.HasField('contacts'):
            raise TypeError('Deprecated contact sync message')
        elif message.HasField('groups'):
            raise TypeError('Deprecated group sync message')
        elif message.HasField('blocked'):
            self.handleBlocked(message.blocked, envelope)
        elif message.HasField('request'):
            raise TypeError('Deprecated group request sync message')
        else:
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

    async def getAttachment(self, attachment):
        """ Download and decrypt attachment pointer. """
        cipher = await self.signal.getAttachment(attachment.id)
        return crypto.decryptAttachment(cipher, attachment.key)

    async def handleEndSession(self, addr):
        device_ids = store.getDeviceIds(addr)
        for device_id in device_ids:
            stores = [store] * 4
            sessionCipher = SessionCipher(*stores, addr, device_id)
            logger.warn('Closing session for: %s %d' % (addr, device_id))
            sessionCipher.closeOpenSessionForDevice()
