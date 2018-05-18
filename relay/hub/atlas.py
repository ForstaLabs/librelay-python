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
from .. import storage
from .. import util

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


class AtlasClient(object):

    def __init__(self, url=None, jwt=None):
        self.url = url or DEFAULT_ATLAS_URL
        if jwt:
            jwt_dict = decode_jwt(jwt)
            self.user_id = jwt_dict['payload']['user_id']
            self.org_id = jwt_dict['payload']['org_id']
            self.auth_header = 'JWT ' + jwt
        else:
            self.auth_header = None
        self._httpClient = aiohttp.ClientSession(read_timeout=30)

    def __del__(self):
        asyncio.get_event_loop().create_task(self._httpClient.close())
        self._httpClient = None

    @classmethod
    def factory(cls):
        url = store.getState(url_store_key)
        jwt = store.getState(cred_store_key)
        return cls(url=url, jwt=jwt)

    @classmethod
    async def request_authentication_code(cls, user_tag, **options):
        client = cls(**options)
        user, org = client.parse_tag(user_tag)
        await client.fetch(f'/v1/login/send/{org}/{user}/')
        return lambda code: cls.authenticate_via_code(user_tag, code, **options)

    @classmethod
    async def authenticate_via_code(cls, user_tag, code, **options):
        client = cls(**options)
        user, org = client.parse_tag(user_tag)
        auth = await client.fetch('/v1/login/authtoken/', method='POST',
                                  json={"authtoken": f'{org}:{user}:{code}'})
        store.putState(cred_store_key, auth['token'])
        store.putState(url_store_key, client.url)
        return cls(url=client.url, jwt=auth['token'])

    @classmethod
    async def authenticateViaToken(cls, userauthtoken, **options):
        client = cls(**options)
        auth = await client.fetch('/v1/login/authtoken/', method="POST",
                                  json={"userauthtoken": userauthtoken})
        store.putState(cred_store_key, auth.token)
        store.putState(url_store_key, client.url)
        return cls(url=client.url, jwt=auth['token'])

    def parse_tag(self, tag):
        user, *org = tag.lstrip('@').split(':', 1)
        if not org:
            org = ['forsta']
        return user, org[0]

    async def fetch(self, urn, method='GET', json=None):
        headers = self.auth_header and {'Authorization': self.auth_header}
        url = f'{self.url}/{urn.lstrip("/")}'
        logger.debug(f"Fetch Request: {urn} {method} {json}")
        async with self._httpClient.request(url=url, method=method, json=json,
                                            headers=headers) as resp:
            is_json = resp.content_type.startswith('application/json')
            result = await resp.json() if is_json else await resp.text()
            logger.debug(f"Fetch Response: {urn} {method}: [{resp.status}] {result}")
            resp.raise_for_status()
            return result

    async def maintain_jwt(self, force_refresh=False, authenticator=None,
                           on_refresh=None):
        """ Manage auth token expiration.  This routine will reschedule itself
        as needed. """
        token = decode_jwt(store.getState(cred_store_key))
        refresh_delay = lambda t: (t['payload']['exp'] - time.time()) / 2
        if force_refresh or refresh_delay(token) < 1:
            encoded_token = store.getState(cred_store_key)
            resp = await self.fetch('/v1/api-token-refresh/', method="POST",
                                    json={"token": encoded_token})
            if not resp or not resp['token']:
                if authenticator:
                    result = await authenticator()
                    logger.info("Reauthenticated user in maintain_jwt")
                    jwt = result.jwt
                else:
                    raise TypeError("Unable to reauthenticate in maintain_jwt")
            else:
                jwt = resp['token']
            token = decode_jwt(jwt)
            logger.info("Refreshed JWT in maintain_jwt")
            store.putState(cred_store_key, jwt)
            self.auth_header = 'JWT ' + jwt
            self.user_id = token['payload']['user_id']
            if on_refresh:
                try:
                    await on_refresh(token)
                except Exception as e:
                    logger.exception('on_refresh callback error')
        next_update = refresh_delay(token)
        logger.info('maintain_jwt will recheck auth token in %f seconds' %
                    next_update)
        await asyncio.sleep(next_update)
        await self.maintain_jwt(False, authenticator, on_refresh)

    async def resolve_tags(self, expression):
        return (await self.resolve_tags_batch([expression]))[0]

    async def resolve_tags_batch(self, expressions):
        if not expressions:
            return []
        resp = await self.fetch('/v1/tagmath/', method='POST',
                                json={"expression": expressions})
        # Enhance the warnings a bit.
        for res, expr in zip(resp.results, expressions):
            for w in res.warnings:
                w.context = expr[w.position, w.position + w.length]
        return resp.results

    def sanitize_tags(self, expression):
        """ Clean up tags a bit. Add @ where needed.
        NOTE: This does not currently support universal format! """
        sep_re = re.compile(r'([\s()^&+-]+)')
        tags = []
        for tag in filter(None, sep_re.split(expression.strip())):
            if re.compile(r'^[a-zA-Z]').match(tag):
                tag = '@' + tag
            tags.append(tag)
        return ' '.join(tags)

    async def get_users(self, user_ids, only_dir=False):
        missing = set(user_ids)
        users = []
        if not only_dir:
            resp = await self.fetch('/v1/user/?id_in=' + ','.join(user_ids))
            for user in resp['results']:
                users.append(user)
                missing.remove(user.id)
        if missing:
            resp = await self.fetch('/v1/directory/user/?id_in=' +
                                    ','.join(missing))
            for user in resp['results']:
                users.append(user)
        return users

    async def get_devices(self):
        try:
            return (await self.fetch('/v1/provision/account'))['devices']
        except util.RequestError as e:
            if e.code == 404:
                return []
            else:
                raise e
