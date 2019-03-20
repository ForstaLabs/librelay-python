import asyncio
import base64
import logging
import secrets

from .. import protobufs
from .. import storage
from ..provisioning_cipher import ProvisioningCipher
from ..websocket_resource import WebSocketResource
from .atlas import AtlasClient
from .signal import SignalClient
from libsignal.identitykey import IdentityKey
from libsignal.identitykeypair import IdentityKeyPair
from libsignal.util.keyhelper import KeyHelper


store = storage.getStore()
logger = logging.getLogger(__name__)
defaultName = 'librelay'


def generatePassword():
    return base64.b64encode(secrets.token_bytes(16)).decode().rstrip('=')


def generateSignalingKey():
    return secrets.token_bytes(32 + 20)


async def registerAccount(atlasClient=None, name=defaultName):
    if atlasClient is None:
        atlasClient = AtlasClient.factory()
    registrationId = KeyHelper.generateRegistrationId()
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
    if not accountInfo['devices']:
        logger.error("Must use `registerAccount` for first device")
        raise TypeError("No Account")
    signalClient = SignalClient(url=accountInfo['serverUrl'])
    if not onProvisionReady and not autoProvision:
        raise TypeError("Missing: onProvisionReady callback")
    returnInterface = {"waiting": True}
    provisioningCipher = ProvisioningCipher()
    pubkey = base64.b64encode(provisioningCipher.getPublicKey().getPublicKey())
    webSocketWaiter = asyncio.Future()

    async def handleRequest(request):
        if request.path == "/v1/address" and request.verb == "PUT":
            proto = protobufs.ProvisioningUuid()
            proto.ParseFromString(request.body)
            await request.respond(200, 'OK')
            if autoProvision:
                await atlasClient.fetch('/v1/provision/request', method='POST', json={
                    "uuid": proto.uuid,
                    "key": pubkey.decode()
                })
            if onProvisionReady:
                raise NotImplementedError("Not ported")
                #r = onProvisionReady(proto.uuid, pubkey)
                #if (r instanceof Promise) {
                #    r.catch(reject)
                #}
        elif request.path == "/v1/message" and request.verb == "PUT":
            msgEnvelope = protobufs.ProvisionEnvelope()
            msgEnvelope.ParseFromString(request.body)
            await request.respond(200, 'OK')
            await wsr.close()
            webSocketWaiter.set_result(msgEnvelope)
        else:
            raise Exception('Unknown websocket message ' + request.path)
    wsr = WebSocketResource(signalClient.getProvisioningWebSocketUrl(), handleRequest)
    await wsr.connect()

    async def _done():
        pmsg = await provisioningCipher.decrypt(await webSocketWaiter)
        returnInterface['waiting'] = False
        addr = pmsg['addr']
        identity = IdentityKeyPair(IdentityKey(pmsg['identityKeyPair'].getPublicKey()),
                                   pmsg['identityKeyPair'].getPrivateKey())
        if pmsg['addr'] != accountInfo['userId']:
            raise Exception('Security Violation: Foreign account sent us an identity key!')
        registrationId = KeyHelper.generateRegistrationId()
        password = generatePassword()
        signalingKey = generateSignalingKey()
        json = {
            "signalingKey": base64.b64encode(signalingKey).decode(),
            "supportsSms": False,
            "fetchesMessages": True,
            "registrationId": registrationId,
            "name": name
        }
        response = await signalClient.request(call='devices', method='PUT',
                                              urn='/' + pmsg['provisioningCode'],
                                              username=addr, password=password,
                                              json=json)
        username = f'{addr}.{response["deviceId"]}'
        store.clearSessionStore()
        store.removeOurIdentity()
        store.removeIdentity(addr)
        store.saveIdentity(addr, identity.getPublicKey())
        store.saveOurIdentity(identity)
        store.putState('addr', addr)
        store.putState('serverUrl', signalClient.url)
        store.putState('deviceId', response['deviceId'])
        store.putState('name', name)
        store.putState('username', username)
        store.putState('password', password)
        store.putState('registrationId', registrationId)
        store.putState('signalingKey', signalingKey)
        authedClient = SignalClient(username, password, signalClient.url)
        await authedClient.registerKeys(await authedClient.generateKeys())
    returnInterface['done'] = asyncio.get_event_loop().create_task(_done())

    async def cancel():
        await wsr.close()
        try:
            await webSocketWaiter
        except Exception as e:
            logger.warn("Ignoring web socket error: " + e)
    returnInterface['cancel'] = cancel

    return returnInterface
