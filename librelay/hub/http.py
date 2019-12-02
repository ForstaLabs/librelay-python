import aiohttp
import contextlib
import logging

logger = logging.getLogger(__name__)


class HttpClient(object):

    def __init__(self, *args, url=None, **kwargs):
        self.url = url
        super().__init__(*args, **kwargs)

    def getHttpSession(self, timeout=300):
        return aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout))

    async def fetch(self, urn, method='GET', **kwargs):
        """ Thin wrapper to augment json and auth support. """
        async with self.fetchRequest(urn, method=method, **kwargs) as resp:
            is_json = resp.content_type.startswith('application/json')
            data = await resp.json() if is_json else await resp.text()
            url = f'{self.url}/{urn.lstrip("/")}'
            logger.debug(f"Fetch {method} response {url}: [{resp.status}]")
            resp.raise_for_status()
            return data

    @contextlib.asynccontextmanager
    async def fetchRequest(self, urn, method='GET', headers=None, json=None,
                           **request_options):
        if headers is None:
            headers = {}
        if 'Authorization' not in headers:
            auth = self.authHeader()
            if auth:
                headers['Authorization'] = auth
        url = f'{self.url}/{urn.lstrip("/")}'
        logger.debug(f"Fetch {method} request {url}")
        async with self.getHttpSession() as s:
            async with s.request(url=url, headers=headers, method=method,
                                 json=json, **request_options) as req:
                yield req

    def authHeader(self):
        """ Optional callback to provide the authorization header in a request. """
        pass
