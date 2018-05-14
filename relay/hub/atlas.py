"""
Atlas API client
"""

import asyncio
import base64
import json
import logging
import re
import requests
import time
from .. import storage
from .. import util

logger = logging.getLogger(__name__)

DEFAULT_ATLAS_URL = 'https://atlas.forsta.io'
cred_store_key = 'atlasCredential'
url_store_key = 'atlasUrl'


def atobJWT(value):
    """ See: https://github.com/yourkarma/JWT/issues/8 """
    return base64.b64decode(value.replace('_', '/').replace('-', '+'))


def decode_jwt(encoded_token):
    parts = [atobJWT(x) for x in encoded_token.split('.')]
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

    def __init__(self, url=DEFAULT_ATLAS_URL, jwt=None):
        self.url = url
        if (jwt):
            jwtDict = decode_jwt(jwt)
            self.user_id = jwtDict['payload']['user_id']
            self.org_id = jwtDict['payload']['org_id']
            self.auth_header = 'JWT ' + jwt

    @classmethod
    async def factory(cls):
        url = await storage.getState(url_store_key)
        jwt = await storage.getState(cred_store_key)
        return cls(url=url, jwt=jwt)

    @classmethod
    async def request_authentication_code(cls, user_tag, **options):
        client = cls(**options)
        user, org = client.parse_tag(user_tag)
        await client.fetch(f'/v1/login/send/{org}/{user}/')
        return lambda code: cls.authenticateViaCode(user_tag, code, **options)

    @classmethod
    async def authenticate_via_code(cls, user_tag, code, **options):
        client = cls(**options)
        user, org = client.parse_tag(user_tag)
        auth = await client.fetch('/v1/login/authtoken/', method='POST',
                                  json={"authtoken": f'{org}:{user}:{code}'})
        await storage.putState(cred_store_key, auth.token)
        await storage.putState(url_store_key, client.url)
        return cls(url=client.url, jwt=auth['token'])

    @classmethod
    async def authenticateViaToken(cls, userauthtoken, **options):
        client = cls(**options)
        auth = await client.fetch('/v1/login/authtoken/', method="POST",
                                  json={"userauthtoken": userauthtoken})
        await storage.putState(cred_store_key, auth.token)
        await storage.putState(url_store_key, client.url)
        return cls(url=client.url, jwt=auth['token'])

    def parse_tag(self, tag):
        user, *org = tag.lstrip('@').split(':', 1)
        if not org:
            org = ['forsta']
        return user, org[0]

    async def fetch(self, urn, method='GET', json=None):
        headers = self.auth_header and {'Authorization': self.auth_header}
        url = f'{self.url}/{urn.lstrip("/")}'
        resp = requests.request(method, url, json=json, headers=headers)
        is_json = resp.headers.get('content-type', '') \
            .startswith('application/json')
        json = resp.json() if is_json else None
        if not resp.ok:
            msg = f'{urn} ({resp.text})'
            raise util.RequestError(msg, resp, resp.status_code, resp.text,
                                    json)
        return json or resp.text

    async def maintain_jwt(self, force_refresh=False, authenticator=None,
                           on_refresh=None):
        """ Manage auth token expiration.  This routine will reschedule itself
        as needed. """
        token = decode_jwt(await storage.getState(cred_store_key))
        refresh_delay = lambda t: (t['payload']['exp'] - time.time()) / 2
        if force_refresh or refresh_delay(token) < 1:
            encoded_token = await storage.getState(cred_store_key)
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
            await storage.putState(cred_store_key, jwt)
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
