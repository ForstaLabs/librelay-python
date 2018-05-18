import base64
import logging
import secrets

from .. import storage
from ..provisioning_cipher import ProvisioningCipher
#from ..websocket_resource import WebSocketResource
from .atlas import AtlasClient
from .signal import SignalClient
from axolotl.util.keyhelper import KeyHelper

store = storage.getStore()
logger = logging.getLogger(__name__)
defaultName = 'librelay'


class ReturnInterface(object):
    pass


def generatePassword():
    return base64.b64encode(secrets.token_bytes(16)).decode().rstrip('=')


def generateSignalingKey():
    return secrets.token_bytes(32 + 20)


async def registerAccount(atlasClient=None, name=defaultName):
    if atlasClient is None:
        atlasClient = AtlasClient.factory()
    # Workaround axolotl bug that generates unsigned ints.
    registrationId = KeyHelper.generateRegistrationId() & 0x7fffffff
    password = generatePassword()
    signalingKey = generateSignalingKey()
    r = await atlasClient.fetch('/v1/provision/account', method="PUT", json={
        "signalingKey": base64.b64encode(signalingKey).decode(),
        "supportsSms": False,
        "fetchesMessages": True,
        "registrationId": registrationId,
        "name": name,
        "password": password
    })
    addr = r['userId']
    username = f'{addr}.{r["deviceId"]}'
    identity = KeyHelper.generateIdentityKeyPair()
    store.clearSessionStore()
    store.removeOurIdentity()
    store.removeIdentity(addr)
    store.saveIdentity(addr, identity.getPublicKey())
    store.saveOurIdentity(identity)
    store.putState('addr', addr)
    store.putState('serverUrl', r['serverUrl'])
    store.putState('deviceId', r['deviceId'])
    store.putState('name', name)
    store.putState('username', username)
    store.putState('password', password)
    store.putState('registrationId', registrationId)
    store.putState('signalingKey', signalingKey)
    sc = SignalClient(username, password, r['serverUrl'])
    await sc.registerKeys(await sc.generateKeys())


async def registerDevice(atlasClient=None, name=defaultName,
                         autoProvision=True, onProvisionReady=None):
    if atlasClient is None:
        atlasClient = AtlasClient.factory()
    accountInfo = await atlasClient.fetch('/v1/provision/account')
    if not accountInfo.devices:
        logger.error("Must use `registerAccount` for first device")
        raise TypeError("No Account")
    signalClient = SignalClient(url=accountInfo.serverUrl)
    if not onProvisionReady and autoProvision:
        raise TypeError("Missing: onProvisionReady callback")
    returnInterface = ReturnInterface()
    returnInterface.waiting = True
    provisioningCipher = ProvisioningCipher()
    pubkey = provisioningCipher.getPublicKey().toString('base64')
    raise Exception('XXX not ported yet')
    '''webSocketWaiter = Promise((resolve, reject) => {
        wsr = WebSocketResource(signalClient.getProvisioningWebSocketURL(), {
            keepalive: {path: '/v1/keepalive/provisioning'},
            handleRequest: request => {
                if (request.path == "/v1/address" and request.verb == "PUT") {
                    proto = protobufs.ProvisioningUuid.decode(request.body)
                    request.respond(200, 'OK')
                    if (autoProvision) {
                        atlasClient.fetch('/v1/provision/request', {
                            method: 'POST',
                            json: {
                                uuid: proto.uuid,
                                key: pubkey
                            }
                        }).catch(reject)
                    }
                    if (options.onProvisionReady) {
                        r = options.onProvisionReady(proto.uuid, pubkey)
                        if (r instanceof Promise) {
                            r.catch(reject)
                        }
                    }
                } else if (request.path == "/v1/message" and request.verb == "PUT") {
                    msgEnvelope = protobufs.ProvisionEnvelope.decode(request.body)
                    request.respond(200, 'OK')
                    wsr.close()
                    resolve(msgEnvelope)
                } else {
                    reject(Exception('Unknown websocket message ' + request.path))
                }
            }
        })
    })
    await wsr.connect()
    '''

    async def _done():
        pmsg = await provisioningCipher.decrypt(await webSocketWaiter)
        returnInterface.waiting = False
        addr = pmsg.addr
        identity = pmsg.identityKeyPair
        if pmsg.addr != accountInfo.userId:
            raise Exception('Security Violation: Foreign account sent us an identity key!')
        # Workaround axolotl bug that generates unsigned ints.
        registrationId = KeyHelper.generateRegistrationId() & 0x7fffffff
        password = generatePassword()
        signalingKey = generateSignalingKey()
        json = {
            "signalingKey": signalingKey.toString('base64'),
            "supportsSms": False,
            "fetchesMessages": True,
            "registrationId": registrationId,
            "name": name
        }
        response = await signalClient.request(call='devices', httpType='PUT',
                                              urn='/' + pmsg.provisioningCode,
                                              username=addr, password=password,
                                              json=json)
        username = f'{addr}.{response.deviceId}'
        store.clearSessionStore()
        store.removeOurIdentity()
        store.removeIdentity(addr)
        store.saveIdentity(addr, identity.publicKey)
        store.saveOurIdentity(identity)
        store.putState('addr', addr)
        store.putState('serverUrl', signalClient.url)
        store.putState('deviceId', response.deviceId)
        store.putState('name', name)
        store.putState('username', username)
        store.putState('password', password)
        store.putState('registrationId', registrationId)
        store.putState('signalingKey', signalingKey)
        authedClient = SignalClient(username, password, signalClient.url)
        await authedClient.registerKeys(await authedClient.generateKeys())
    done = _done()

    async def cancel():
        wsr.close()
        try:
            await webSocketWaiter
        except Exception as e:
            logger.warn("Ignoring web socket error: " + e)
    returnInterface.cancel = cancel

    return returnInterface
