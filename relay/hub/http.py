import aiohttp
import asyncio
import logging

logger = logging.getLogger(__name__)


class HttpClient(object):

    def __init__(self, *args, url=None, **kwargs):
        self.url = url
        self.httpSession = aiohttp.ClientSession(read_timeout=30)
        super().__init__(*args, **kwargs)

    def __del__(self):
        loop = asyncio.get_event_loop()
        if not loop.is_closed():
            loop.create_task(self.httpSession.close())
        self.httpSession = None

    async def fetch(self, urn, method='GET', **kwargs):
        """ Thin wrapper to augment json and auth support. """
        async with self.fetchRequest(urn, method=method, **kwargs) as resp:
            is_json = resp.content_type.startswith('application/json')
            data = await resp.json() if is_json else await resp.text()
            url = f'{self.url}/{urn.lstrip("/")}'
            logger.debug(f"Fetch {method} response {url}: [{resp.status}]")
            resp.raise_for_status()
            return data

    def fetchRequest(self, urn, method='GET', headers=None, json=None,
                     **request_options):
        if headers is None:
            headers = {}
        if 'Authorization' not in headers:
            auth = self.authHeader()
            if auth:
                headers['Authorization'] = auth
        url = f'{self.url}/{urn.lstrip("/")}'
        logger.debug(f"Fetch {method} request {url}")
        return self.httpSession.request(url=url, headers=headers, method=method,
                                        json=json, **request_options)

    def authHeader(self):
        """ Optional callback to provide the authorization header in a request. """
        pass
