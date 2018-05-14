import aiohttp
import logging
import re
import urllib
#from .. import protobufs
from .. import storage
from ..provisioning_cipher import ProvisioningCipher
from axolotl.util import KeyHelper
from base64 import b64decode, b64encode

logger = logging.getLogger(__name__)

SIGNAL_URL_CALLS = {
    "accounts": "/v1/accounts",
    "devices": "/v1/devices",
    "keys": "/v2/keys",
    "messages": "/v1/messages",
    "attachment": "/v1/attachments"
}

SIGNAL_HTTP_MESSAGES = {
    401: "Invalid authentication or invalidated registration",
    403: "Invalid code",
    404: "Address is not registered",
    413: "Server rate limit exceeded",
    417: "Address already registered"
}


class SignalClient(object):

    attachment_id_regex = re.compile("^https://.*/(\\d+)?")

    def __init__(self, username, password, url):
        self.url = url
        self.username = username
        self.password = password
        self._httpClient = aiohttp.ClientSession(read_timeout=30,
                                                 raise_for_status=True)

    def __del__(self):
        self._httpClient.close()
        self._httpClient = None

    @classmethod
    async def factory(cls):
        url = await storage.get_state('server_url')
        username = await storage.get_state('username')
        password = await storage.get_state('password')
        return cls(username, password, url)

    async def link_device(self, uuid, pubkey, userAgent='librelay-python'):
        provision_resp = await self.request(call='devices',
                                            urn='/provisioning/code')
        our_ident = await storage.get_our_identity()
        pMessage = protobufs.ProvisionMessage()
        pMessage.identityKeyPrivate = our_ident.privKey
        pMessage.addr = await storage.get_state('addr')
        pMessage.userAgent = userAgent
        pMessage.provisioningCode = provision_resp.verificationCode
        provisioningCipher = ProvisioningCipher()
        pEnvelope = await provisioningCipher.encrypt(pubkey, pMessage)
        try:
            async with await self.fetch('/v1/provisioning/' + uuid, method='PUT',
                                        json={"body": b64encode(pEnvelope)}):
                pass
        except aiohttp.ClientResponseError as e:
            # 404 is okay, just means someone else handled it already.
            if e.status != 404:
                raise e

    async def refresh_prekeys(self, minLevel=10, fill=100):
        preKeyCount = await self.getMyKeys()
        if preKeyCount <= minLevel:
            # The server replaces existing keys so just go to the hilt.
            logger.info("Refreshing pre-keys...")
            await self.registerKeys(await self.generate_keys(fill))

    async def generate_keys(self, count=100, progressCallback=None):
        start_id = await storage.get_state('max_prekey_id') or 1
        signed_key_id = await storage.get_state('signed_key_id') or 1
        our_ident = await storage.get_our_identity()
        result = {
            "prekeys": [],
            "identity_key": our_ident.pubkey,
        }
        for key_id in range(start_id, start_id + count):
            preKey = await KeyHelper.generatePreKey(key_id)
            await storage.storePreKey(preKey.keyId, preKey.keyPair)
            result.preKeys.push({
                "keyId": preKey['keyId'],
                "publicKey": preKey['keyPair']['pubkey']
            })
            if progressCallback:
                progressCallback(key_id - start_id)
        sprekey = await KeyHelper.generateSignedPreKey(our_ident, signed_key_id)
        await storage.storeSignedPreKey(sprekey.keyId, sprekey.keyPair)
        result.signedPreKey = {
            "keyId": sprekey['keyId'],
            "publicKey": sprekey['keyPair']['pubkey'],
            "signature": sprekey['signature']
        }
        await storage.removeSignedPreKey(signed_key_id - 2)
        await storage.putState('max_prekey_id', start_id + count)
        await storage.putState('signed_key_id', signed_key_id + 1)
        return result

    def auth_header(self, username, password):
        return 'Basic ' + b64encode(username + ':' + password)

    async def request(self, call=None, urn='', method='GET',
                      json=None, username=None, password=None):
        path = SIGNAL_URL_CALLS.get(call) + urn
        headers = {}
        if username and password:
            headers['Authorization'] = self.auth_header(username, password)
        async with await self.fetch(path, method=method, json=json,
                                    headers=headers) as r:
            is_json = r.content_type.startswith('application/json')
            resp_content = await r.json() if is_json else await r.text()
        # Can we just use native exceptions from aiohttp?? please
        #if not resp.ok:
        #    e = errors.ProtocolError(resp.status, resp_content)
        #    if e.code in SIGNAL_HTTP_MESSAGES:
        #        e.message = SIGNAL_HTTP_MESSAGES[e.code]
        #    else:
        #        e.message = f'Status code: {e.code}'
        #    raise e
        return resp_content

    async def fetch(self, urn, headers=None, **kwargs):
        """ Thin wrapper to augment json and auth support. """
        if headers is None:
            headers = {}
        if 'Authorization' not in headers and self.username and self.password:
            headers['Authorization'] = self.auth_header(self.username,
                                                        self.password)
        return self._httpClient.request(url=f'{self.url}/{urn.lstrip("/")}',
                                        headers=headers, **kwargs)

    async def get_devices(self):
        data = await self.request(call='devices')
        return data and data['devices']

    async def register_keys(self, keys):
        json = {}
        json['identityKey'] = b64encode(keys['identityKey'])
        json['signedPreKey'] = {
            "keyId": keys['signedPreKey']['keyId'],
            "publicKey": b64encode(keys['signedPreKey']['publicKey']),
            "signature": b64encode(keys['signedPreKey']['signature'])
        }
        json.preKeys = []
        for pk in keys['prekeys']:
            json.append({
                "keyId": pk['keyId'],
                "publicKey": b64encode(pk['publicKey'])
            })
        return await self.request(call='keys', method='PUT', json=json)

    async def get_my_keys(self):
        res = await self.request(call='keys')
        return res.count

    async def get_keys_for_addr(self, addr, device_id='*'):
        res = await self.request(call='keys',
                                 urn=f'/{addr}/{device_id}')
        res['identityKey'] = b64decode(res['identityKey'])
        for device in res['devices']:
            if device['preKey']:
                device['preKey']['publicKey'] = b64decode(device['preKey']['publicKey'])
            device['signedPreKey']['publicKey'] = b64encode(device['signedPreKey']['publicKey'])
            device['signedPreKey']['signature'] = b64encode(device['signedPreKey']['signature'])
        return res

    async def send_messages(self, destination, messages, timestamp):
        return await self.request(call='messages', method='PUT',
                                  urn='/' + destination,
                                  json={"messages": messages,
                                        "timestamp": timestamp})

    async def get_attachment(self, id):
        """ XXX Build in retry handling... """
        ptr_resp = await self.request(call='attachment', urn='/' + id)
        async with self._httpClient.get(ptr_resp['location']) as r:
            return await r.read()

    async def put_attachment(self, body):
        """ XXX Build in retry handling... """
        ptr_resp = await self.request(call='attachment')
        # Extract the id as a string from the location url
        # (workaround for ids too large for Javascript numbers) # XXX
        import pdb;pdb.set_trace()
        match = self.attachment_id_regex.match(ptr_resp['location'])
        if not match:
            logger.error('Invalid attachment url for outgoing message',
                          ptr_resp['location'])
            raise TypeError('Received invalid attachment url')
        async with self._httpClient.put(ptr_resp['location'], data=body):
            pass
        return match[1]

    def get_message_websocket_url(self):
        return ''.join([
            self.url.replace('https://', 'wss://').replace('http://', 'ws://'),
            '/v1/websocket/?login=', urllib.quote(self.username),
            '&password=', urllib.quote(self.password)
        ])

    def get_provisioning_websocket_url(self):
        return self.url.replace('https://', 'wss://').replace('http://', 'ws://') + \
                                '/v1/websocket/provisioning/'

    async def updateGcmRegistrationId(self, gcm_reg_id):
        """ The GCM reg ID configures the data needed for the PushServer to
        wake us up using google cloud messaging's Push Server (an exercise for
        the user). """
        return await self.request(call='accounts', method='PUT', urn='/gcm',
            json={"gcmRegistrationId": gcm_reg_id})
