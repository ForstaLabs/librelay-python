import asyncio
import base64
import datetime
import logging
import traceback
from . import errors, storage, protobufs
from .queue_async import queue_async
from axolotl.sessionbuilder import SessionBuilder
from axolotl.sessioncipher import SessionCipher
from axolotl.state.prekeybundle import PreKeyBundle
from axolotl.untrustedidentityexception import UntrustedIdentityException

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

    def on(self, event, callback):
        handlers = self._listeners.get(event)
        if not handlers:
            handlers = self._listeners[event] = []
        handlers.append(callback)

    async def emit(self, event, *args, **kwargs):
        handlers = self._listeners.get(event)
        if not handlers:
            return
        for callback in handlers:
            try:
                await callback(*args, **kwargs)
            except Exception as e:
                logger.exception("Event callback error")

    async def emitError(self, addr, reason, error):
        trace = ''.join(traceback.format_exception(type(error), error,
                                                     error.__traceback__))
        logger.error(f'{reason}: {error}\n{trace}')
        if not error or isinstance(error, errors.ProtocolError) and \
           error.code != 404:
            error = errors.OutgoingMessageError(addr, self.message,
                                                self.timestamp, error)
        error.addr = addr
        error.reason = reason
        entry = {
            "timestamp": msnow(),
            "error": error
        }
        self.errors.append(entry)
        await self.emit('error', entry)

    async def emitSent(self, addr):
        entry = {
            "timestamp": msnow(),
            "addr": addr
        }
        self.sent.append(entry)
        await self.emit('sent', entry)

    async def getKeysForAddr(self, addr, devices=None, _retries=0):
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
                    keyError = errors.OutgoingIdentityKeyError(addr,
                                                               remoteIdent)
                    if not _retries:
                        await self.emit('keychange', keyError)
                        if not keyError.accepted:
                            raise keyError
                        await self.getKeysForAddr(addr, devices,
                                                  _retries=_retries+1)
                    else:
                        raise keyError
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

    async def transmitMessage(self, addr, json, timestamp):
        try:
            return await self.signal.sendMessages(addr, json, timestamp)
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

    async def _sendToAddr(self, addr, _retries=0):
        buf = self.message.SerializeToString()
        minLen = self.getPaddedMessageLength(len(buf) + 1) - 1
        paddedBuf = buf + b'\x80' + (b'\00' * (minLen - len(buf) - 1))
        messages = []
        stores = [store] * 4
        ciphers = {}
        for x in store.getDeviceIds(addr):
            ciphers[x] = sc = SessionCipher(*stores, addr, x)
            state = store.loadSession(addr, x).getSessionState()
            regId = state.getRemoteRegistrationId(None)
            messages.append(self.encryptToDevice(x, regId, paddedBuf, sc))
        try:
            await self.transmitMessage(addr, messages, self.timestamp)
        except errors.ProtocolError as e:
            if e.code in (409, 410):
                if _retries >= 2:
                    raise RuntimeError("Too many retries updating remote keys")
                elif e.code == 409:
                    self.deleteSessions(addr, e.response['extraDevices'])
                else:
                    for x in e.response['staleDevices']:
                        ciphers[x].closeOpenSessionForDevice()
                update = e.response.get('staleDevices', []) + \
                         e.response.get('missingDevices', [])
                await self.getKeysForAddr(addr, devices=update)
                await self._sendToAddr(addr, _retries=_retries+1)
            else:
                await self.emitError(addr, "Failed to send message", e)
                raise
        else:
            await self.emitSent(addr)

    def encryptToDevice(self, deviceId, deviceRegId, buf, sessionCipher):
        msg = sessionCipher.encrypt(buf)
        return {
            "type": {
                msg.PREKEY_TYPE: protobufs.Envelope.PREKEY_BUNDLE,
                msg.WHISPER_TYPE: protobufs.Envelope.CIPHERTEXT,
            }[msg.getType()],
            "destinationDeviceId": deviceId,
            "destinationRegistrationId": deviceRegId,
            "content": base64.b64encode(msg.serialize()).decode()
        }

    def deleteSessions(self, addr, deviceIds):
        for x in deviceIds:
            store.deleteSession(addr, x)

    async def sendToAddr(self, addr):
        """ Serialized send routine that protects session from corruption. """
        bucket = f'outgoing-msg-{addr}'
        try:
            await queue_async(bucket, self._sendToAddr(addr))
        except Exception as e:
            await self.emitError(addr, "Send error", e)
            raise
