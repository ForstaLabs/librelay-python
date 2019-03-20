"""
Atlas API client
"""

import aiohttp
import asyncio
import base64
import json
import logging
import re
import time
from . import http
from .. import storage

store = storage.getStore()
logger = logging.getLogger(__name__)

DEFAULT_ATLAS_URL = 'https://atlas.forsta.io'
cred_store_key = 'atlasCredential'
url_store_key = 'atlasUrl'


def jwt_b64decode(value):
    padding = 4 - (len(value) % 4)
    return base64.urlsafe_b64decode(value + ("=" * padding))


def decode_jwt(encoded_token):
    parts = [jwt_b64decode(x) for x in encoded_token.split('.')]
    token = {
        "header": json.loads(parts[0]),
        "payload": json.loads(parts[1]),
        "secret": parts[2]
    }
    if not token['payload'] or not token['payload']['exp']:
        raise TypeError("Invalid Token")
    if token['payload']['exp'] <= time.time():
        raise ValueError("Expired Token")
    return token


class AtlasClient(http.HttpClient):

    def __init__(self, url=None, jwt=None):
        self.setJWT(jwt)
        super().__init__(url=url or DEFAULT_ATLAS_URL)

    def setJWT(self, jwt):
        if jwt is not None:
            jwtDict = decode_jwt(jwt)
            self.userId = jwtDict['payload']['user_id']
            self.orgId = jwtDict['payload']['org_id']
            self._authHeader = 'JWT ' + jwt
        else:
            self.userId = None
            self.orgId = None
            self._authHeader = None

    def authHeader(self):
        return self._authHeader

    @classmethod
    def factory(cls):
        url = store.getState(url_store_key)
        jwt = store.getState(cred_store_key)
        return cls(url=url, jwt=jwt)

    @classmethod
    async def requestAuthentication(cls, userTag, **options):
        client = cls(**options)
        user, org = client.parseTag(userTag)
        async with client.fetchRequest(f'/v1/login/send/{org}/{user}/') as resp:
            data = await resp.json()
            if resp.status == 409:
                if 'totp auth required' in data['non_field_errors']:
                    auth_type = 'totp'

                    async def validator(password, otp):
                        return await cls.authenticateViaPasswordOtp(userTag,
                            password, otp, **options)
                else:
                    auth_type = 'password'

                    async def validator(password):
                        return await cls.authenticateViaPassword(userTag, password, **options)
            else:
                auth_type = 'sms'

                async def validator(code):
                    return await cls.authenticateViaCode(userTag, code, **options)
            return auth_type, validator

    @classmethod
    async def requestAuthenticationCode(cls, userTag, **options):
        client = cls(**options)
        user, org = client.parseTag(userTag)
        await client.fetch(f'/v1/login/send/{org}/{user}/')
        return lambda code: cls.authenticateViaCode(userTag, code, **options)

    @classmethod
    async def authenticateViaCode(cls, userTag, code, **options):
        client = cls(**options)
        user, org = client.parseTag(userTag)
        await client.authenticate(authtoken=f'{org}:{user}:{code}')
        return client

    @classmethod
    async def authenticateViaToken(cls, userauthtoken, **options):
        client = cls(**options)
        await client.authenticate(userauthtoken=userauthtoken)
        return client

    @classmethod
    async def authenticateViaPassword(cls, fq_tag, password, **options):
        client = cls(**options)
        await client.authenticate(fq_tag=fq_tag, password=password)
        return client

    @classmethod
    async def authenticateViaPasswordOtp(cls, fq_tag, password, otp, **options):
        client = cls(**options)
        await client.authenticate(fq_tag=fq_tag, password=password, otp=otp)
        return client

    async def authenticate(self, **creds):
        """ Creds should be an object of these supported forms..
            1. Password auth:
                 fq_tag: "@foo:bar",
                 password: "secret"
            1.5 Password+TOTP auth:
                 fq_tag: "@foo:bar",
                 password: "secret"
                 otp: "code"
            2. SMS auth:
                 authtoken: "123456",
            3. Token auth:
                 userauthtoken: "APITOKEN",
        """
        auth = await self.fetch('/v1/login/', method='POST', json=creds)
        self.setJWT(auth['token'])
        store.putState(cred_store_key, auth['token'])
        store.putState(url_store_key, self.url)

    def parseTag(self, tag):
        user, *org = tag.lstrip('@').split(':', 1)
        if not org:
            org = ['forsta']
        return user, org[0]

    async def maintainJWT(self, forceRefresh=False, authenticator=None,
                          onRefresh=None):
        """ Manage auth token expiration.  This routine will reschedule itself
        as needed. """
        token = decode_jwt(store.getState(cred_store_key))
        refresh_delay = lambda t: (t['payload']['exp'] - time.time()) / 2
        if forceRefresh or refresh_delay(token) < 1:
            encoded_token = store.getState(cred_store_key)
            resp = await self.fetch('/v1/api-token-refresh/', method="POST",
                                    json={"token": encoded_token})
            if not resp or not resp['token']:
                if authenticator:
                    result = await authenticator()
                    logger.info("Reauthenticated user in maintainJWT")
                    jwt = result.jwt
                else:
                    raise TypeError("Unable to reauthenticate in maintainJWT")
            else:
                jwt = resp['token']
            token = decode_jwt(jwt)
            logger.info("Refreshed JWT in maintainJWT")
            store.putState(cred_store_key, jwt)
            self.setJWT(jwt)
            if onRefresh:
                try:
                    await onRefresh(token)
                except Exception as e:
                    logger.exception('on_refresh callback error')
        next_update = refresh_delay(token)
        logger.info('maintainJWT will recheck auth token in %f seconds' %
                    next_update)
        await asyncio.sleep(next_update)
        await self.maintainJWT(False, authenticator, onRefresh)

    async def resolveTags(self, expression):
        return (await self.resolveTagsBatch([expression]))[0]

    async def resolveTagsBatch(self, expressions):
        if not expressions:
            return []
        resp = await self.fetch('/v1/tagmath/', method='POST',
                                json={"expressions": expressions})
        # Enhance the warnings a bit.
        for res, expr in zip(resp['results'], expressions):
            for w in res['warnings']:
                w['context'] = expr[w['position']:w['position']+w['length']]
        return resp['results']

    def sanitizeTags(self, expression):
        """ Clean up tags a bit. Add @ where needed.
        NOTE: This does not currently support universal format! """
        sep_re = re.compile(r'([\s()^&+-]+)')
        tags = []
        for tag in filter(None, sep_re.split(expression.strip())):
            if re.compile(r'^[a-zA-Z]').match(tag):
                tag = '@' + tag
            tags.append(tag)
        return ' '.join(tags)

    async def getUsers(self, userIds, onlyDir=False):
        missing = set(userIds)
        users = []
        if not onlyDir:
            resp = await self.fetch('/v1/user/?id_in=' + ','.join(userIds))
            for user in resp['results']:
                users.append(user)
                missing.remove(user.id)
        if missing:
            resp = await self.fetch('/v1/directory/user/?id_in=' +
                                    ','.join(missing))
            for user in resp['results']:
                users.append(user)
        return users

    async def getDevices(self):
        try:
            return (await self.fetch('/v1/provision/account'))['devices']
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                return []
            else:
                raise e
