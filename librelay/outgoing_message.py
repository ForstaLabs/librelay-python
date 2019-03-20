import asyncio
import base64
import datetime
import inspect
import logging
from . import errors, storage, protobufs
from .queue_async import queue_async
from libsignal.sessionbuilder import SessionBuilder
from libsignal.sessioncipher import SessionCipher
from libsignal.state.prekeybundle import PreKeyBundle
from libsignal.untrustedidentityexception import UntrustedIdentityException

logger = logging.getLogger(__name__)
store = storage.getStore()


def msnow():
    return round(datetime.datetime.now().timestamp() * 1000)


class OutgoingMessage(object):

    def __init__(self, signal, timestamp, message):
        self.signal = signal
        self.timestamp = timestamp
        self.message = message
        self.sent = []
        self.errors = []
        self.created = msnow()
        self._listeners = {}
        self._ourAddr = store.getState('addr');
        self._ourDeviceId = store.getState('deviceId');

    def on(self, event, callback):
        handlers = self._listeners.get(event)
        if not handlers:
            handlers = self._listeners[event] = []
        handlers.append(callback)

    async def _emit(self, event, *args, **kwargs):
        handlers = self._listeners.get(event)
        if not handlers:
            return
        for callback in handlers:
            try:
                r = callback(*args, **kwargs)
                if inspect.isawaitable(r):
                    await r
            except Exception as e:
                logger.exception("Event callback error")

    def _emitError(self, addr, reason, error):
        error.addr = addr
        error.reason = reason
        self._emitErrorEntry({
            "timestamp": msnow(),
            "error": error
        })

    def _emitErrorEntry(self, entry):
        self.errors.append(entry)
        loop = asyncio.get_event_loop()
        loop.create_task(self._emit('error', entry))

    def _emitSent(self, addr):
        self._emitSentEntry({
            "timestamp": msnow(),
            "addr": addr
        })

    def _emitSentEntry(self, entry):
        self.sent.append(entry)
        loop = asyncio.get_event_loop()
        loop.create_task(self._emit('sent', entry))

    async def _handleIdentityKeyError(self, e):
        assert isinstance(e, UntrustedIdentityException)
        entry = {
            "key_error": e,
            "accepted": False
        }
        await self._emit('keychange', entry)
        if not entry['accepted']:
            raise e

    async def getKeysForAddr(self, addr, devices=None, _reentrant=False):
        our_ident = None

        async def buildSessions(remoteIdent, deviceKeys):
            """ Start new sessions (eg. prekeybundles) for this addr.  If
            devices is present, only produce sessions for the ids in that
            sequence.  """
            for keys in deviceKeys:
                if devices is not None and keys['deviceId'] not in devices:
                    raise Exception("Dumb check, never true!")
                    continue
                stores = [store] * 4
                builder = SessionBuilder(*stores, addr, keys['deviceId'])
                pk = keys['preKey'] or {}
                spk = keys['signedPreKey']
                nonlocal our_ident
                if our_ident is None:
                    our_ident = store.getIdentityKeyPair()
                pkb = PreKeyBundle(keys['registrationId'], keys['deviceId'],
                                   pk.get('keyId'), pk.get('publicKey'),
                                   spk['keyId'], spk['publicKey'],
                                   spk['signature'], remoteIdent)
                try:
                    builder.processPreKeyBundle(pkb)
                except UntrustedIdentityException as e:
                    if not _reentrant:
                        await self._handleIdentityKeyError(e)
                    else:
                        raise
                    await self.getKeysForAddr(addr, devices, _reentrant=True)
        if devices is None:
            data = await self.signal.getKeysForAddr(addr)
            ident = data['identityKey']
            keys = data['devices']
        else:
            # Consolodate multiple keys API requests into single entry.
            keys = []
            ident = None
            for f in asyncio.as_completed([self.signal.getKeysForAddr(addr, x)
                                           for x in devices]):
                data = await f
                if not ident:
                    ident = data['identityKey']
                keys.extend(data['devices'])
        try:
            await buildSessions(ident, keys)
        except errors.ProtocolError as e:
            import pdb;pdb.set_trace() # Catch just protocol error for 404 XXX
            if isinstance(e, errors.ProtocolError) and e.code == 404:
                logger.warning(f'Unregistered address (no devices): {addr}')
                self.deleteSessions(addr, [x['deviceId'] for x in keys])
            else:
                raise

    async def _sendMessages(self, addr, messages, timestamp):
        try:
            return await self.signal.sendMessages(addr, messages, timestamp)
        except errors.ProtocolError as e:
            if e.code == 404:
                raise errors.UnregisteredUserError(addr, e)
            else:
                raise

    def getPaddedMessageLength(self, messageLength):
        messageLengthWithTerminator = messageLength + 1
        messagePartCount = messageLengthWithTerminator //160
        if messageLengthWithTerminator % 160 != 0:
            messagePartCount += 1
        return messagePartCount * 160

    async def _sendToAddr(self, addr, _reentrant=False):
        buf = self.message.SerializeToString()
        minLen = self.getPaddedMessageLength(len(buf) + 1) - 1
        paddedBuf = buf + b'\x80' + (b'\00' * (minLen - len(buf) - 1))
        deviceIds = store.getDeviceIds(addr)
        stores = [store] * 4
        for attempt in range(2):
            ciphers = {}
            messages = []
            try:
                for x in deviceIds:
                    ciphers[x] = sc = SessionCipher(*stores, addr, x)
                    state = store.loadSession(addr, x).getSessionState()
                    regId = state.getRemoteRegistrationId(None)
                    messages.append(self.encryptToDevice(x, regId, paddedBuf,
                                                         sc))
                break
            except UntrustedIdentityException as e:
                if not attempt:
                    await self._handleIdentityKeyError(e)
                else:
                    raise
            except Exception as e:
                self._emitError(addr, 'Failed to create message', e)
                raise
        try:
            await self._sendMessages(addr, messages, self.timestamp)
        except errors.ProtocolError as e:
            if e.code not in (409, 410) or _reentrant:
                self._emitError(addr, "Failed to send message", e)
                raise
            if e.code == 409:
                self.deleteSessions(addr, e.response['extraDevices'])
            else:
                for x in e.response['staleDevices']:
                    ciphers[x].closeOpenSessionForDevice()
            update = e.response.get('staleDevices', []) + \
                     e.response.get('missingDevices', [])
            await self.getKeysForAddr(addr, devices=update)
            await self._sendToAddr(addr, _reentrant=True)
        else:
            self._emitSent(addr)

    async def _sendToDevice(self, addr, deviceId, _reentrant=False):
        buf = self.message.SerializeToString()
        minLen = self.getPaddedMessageLength(len(buf) + 1) - 1
        paddedBuf = buf + b'\x80' + (b'\00' * (minLen - len(buf) - 1))
        stores = [store] * 4
        sessionCipher = SessionCipher(*stores, addr, deviceId)
        state = store.loadSession(addr, deviceId).getSessionState()
        regId = state.getRemoteRegistrationId(None)
        for attempt in range(2):
            try:
                messageBundle = self.encryptToDevice(deviceId, regId, paddedBuf,
                                                     sessionCipher)
            except UntrustedIdentityException as e:
                if not attempt:
                    await self._handleIdentityKeyError(e)
                else:
                    raise
        try:
            await self.signal.sendMessage(addr, deviceId, messageBundle)
        except errors.ProtocolError as e:
            if e.code != 410 or _reentrant:
                self._emitError(addr, "Failed to send message", e)
                raise
            sessionCipher.closeOpenSession()
            await self._sendToDevice(addr, deviceId, _reentrant=True)
        else:
            self._emitSent(addr)

    def encryptToDevice(self, deviceId, deviceRegId, buf, sessionCipher):
        msg = sessionCipher.encrypt(buf)
        return {
            "type": {
                msg.PREKEY_TYPE: protobufs.Envelope.PREKEY_BUNDLE,
                msg.WHISPER_TYPE: protobufs.Envelope.CIPHERTEXT,
            }[msg.getType()],
            "destinationDeviceId": deviceId,
            "destinationRegistrationId": deviceRegId,
            "content": base64.b64encode(msg.serialize()).decode(),
            "timestamp": self.timestamp
        }

    def deleteSessions(self, addr, deviceIds):
        for x in deviceIds:
            store.deleteSession(addr, x)

    async def sendToAddr(self, addr):
        """ Serialized send routine that protects session from corruption. """
        try:
            addr, deviceId = addr.split('.')
        except ValueError:
            deviceId = None
        else:
            deviceId = int(deviceId)
        bucket = f'outgoing-msg-{addr}'
        try:
            if deviceId is not None:
                await queue_async(bucket, self._sendToDevice(addr, deviceId))
            else:
                await queue_async(bucket, self._sendToAddr(addr))
        except Exception as e:
            self._emitError(addr, "Send error", e)
            raise
