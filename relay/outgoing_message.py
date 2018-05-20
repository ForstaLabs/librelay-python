
import base64
import datetime
import logging
import traceback
from . import errors, storage
from axolotl.ecc.curve import Curve
from axolotl.sessionbuilder import SessionBuilder
from axolotl.sessioncipher import SessionCipher
from axolotl.state.prekeybundle import PreKeyBundle

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

    async def _sendToAddr(self, addr, recurse=False):
        deviceIds = store.getDeviceIds(addr)
        return await self.doSendMessage(addr, deviceIds, recurse=recurse)

    async def getKeysForAddr(self, addr, updateDevices=None, reentrant=False):

        our_ident = None

        async def buildSessions(remote_keys):
            """ Start new sessions (eg. prekeybundles) for this addr.  If devices
            is present, only produce sessions for the ids in that sequence.  """
            for device in remote_keys['devices']:
                if updateDevices is not None and \
                   device['deviceId'] not in updateDevices:
                    continue
                stores = [store] * 4
                builder = SessionBuilder(*stores, addr, device['deviceId'])
                pk = device['preKey'] or {}
                spk = device['signedPreKey']
                nonlocal our_ident
                if our_ident is None:
                    our_ident = store.getIdentityKeyPair()
                sig = Curve.calculateSignature(our_ident.getPrivateKey(),
                                               spk['publicKey'].serialize())
                pkb = PreKeyBundle(device['registrationId'],
                                   device['deviceId'], pk.get('keyId'),
                                   pk.get('publicKey'), spk['keyId'],
                                   spk['publicKey'], spk['signature'], #sig,
                                   remote_keys['identityKey'])
                                   #our_ident.getPublicKey())
                builder.processPreKeyBundle(pkb)
                try:
                    None
                except Exception as e:
                    # XXX
                    print(e)
                    print(type(e))
                    print(e)
                    if e.message == "Identity key changed":
                        import pdb;pdb.set_trace()
                        keyError = errors.OutgoingIdentityKeyError(addr,
                            self.message, self.timestamp, device['identityKey'])
                        keyError.stack = e.stack
                        keyError.message = e.message
                        if not reentrant:
                            await self.emit('keychange', keyError)
                            if not keyError.accepted:
                                raise keyError
                            await self.getKeysForAddr(addr, updateDevices,
                                                      reentrant=True)
                        else:
                            raise keyError
                    else:
                        raise e

        if updateDevices is None:
            try:
                await buildSessions(await self.signal.getKeysForAddr(addr))
            except Exception as e:
                print('xxxxxxx', e)
                import pdb;pdb.set_trace() # Catch just protocol error for 404 XXX
                if isinstance(e, errors.ProtocolError) and e.code == 404:
                    logger.warning(f'Unregistered address (no devices): {addr}')
                    self.removeDeviceIdsForAddr(addr)
                else:
                    raise
        else:
            for device in updateDevices:
                await buildSessions(await self.signal.getKeysForAddr(addr, device))
                try:
                    #await buildSessions(await self.signal.getKeysForAddr(addr, device))
                    pass
                except Exception as e:
                    print('xxxxxxx', e)
                    import pdb;pdb.set_trace() # Catch just protocol error for 404 XXX
                    if isinstance(e, errors.ProtocolError) and e.code == 404:
                        self.removeDeviceIdsForAddr(addr, [device])
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

    async def doSendMessage(self, addr, deviceIds, recurse):
        ciphers = {}
        buf = self.message.SerializeToString()
        minLen = self.getPaddedMessageLength(len(buf) + 1) - 1
        paddedBuf = buf + b'\x80' + (b'\00' * (minLen - len(buf) - 1))
        messages = []
        stores = [store] * 4
        for x in deviceIds:
            try:
                ciphers[x] = sc = SessionCipher(*stores, addr, x)
                state = store.loadSession(addr, x).getSessionState()
                messages.append(self.encryptToDevice(x, state.getRemoteRegistrationId(None), paddedBuf, sc))
            except Exception as e:
                await self.emitError(addr, "Failed to create message", e)
                return
        try:
            await self.transmitMessage(addr, messages, self.timestamp)
        except errors.ProtocolError as e:
            if e.code in (409, 410):
                if not recurse:
                    await self.emitError(addr, "Hit retry limit attempting " \
                                         "to reload device list", e)
                    return
                if e.code == 409:
                    self.removeDeviceIdsForAddr(addr, e.response['extraDevices'])
                else:
                    for x in e.response['staleDevices']:
                        ciphers[x].closeOpenSessionForDevice()
                resetDevices = e.response['staleDevices'] if e.code == 410 \
                    else e.response['missingDevices']
                await self.getKeysForAddr(addr, resetDevices)
                try:
                    await self._sendToAddr(addr, recurse=(e.code==409))
                except Exception as e:
                    # XXX
                    await self.emitError(addr, "Failed to reload device keys",
                                         e)
                    return
            else:
                await self.emitError(addr, "Failed to send message", e)
        except Exception as e:
            await self.emitError(addr, "Failed to send message", e)
        else:
            await self.emitSent(addr)

    def encryptToDevice(self, deviceId, deviceRegId, buf, sessionCipher):
        msg = sessionCipher.encrypt(buf)
        return {
            "type": msg.getType(),
            "destinationDeviceId": deviceId,
            "destinationRegistrationId": deviceRegId,
            "content": base64.b64encode(msg.serialize()).decode()
        }

    async def reopenClosedSessions(self, addr):
        """ Scan the address for devices that have closed sessions and fetch
        new key material for said devices so we can encrypt messages for them.
        """
        deviceIds = store.getDeviceIds(addr)
        if not deviceIds:
            return
        stores = [store] * 4
        stale = [x for x in deviceIds
                 if not SessionCipher(*stores, addr, x).hasOpenSession()]
        if len(stale) == len(deviceIds):
            logger.info(f'Reopening ALL sessions for: {addr}')
            await self.getKeysForAddr(addr)
        elif stale:
            logger.info(f'Reopening {len(stale)} sessions for: {addr}')
            await self.getKeysForAddr(addr, stale);

    def removeDeviceIdsForAddr(self, addr, deviceIdsToRemove=None):
        if deviceIdsToRemove is None:
            store.removeAllSessions(addr)
        else:
            for x in deviceIdsToRemove:
                store.removeSession(addr + "." + x)

    async def sendToAddr(self, addr):
        try:
            await self.reopenClosedSessions(addr)
        except Exception as e:
            await self.emitError(addr, "Session error", e)
            raise
        try:
            await self._sendToAddr(addr, recurse=True)
        except Exception as e:
            await self.emitError(addr, "Send error", e)
            raise
