import aiohttp
import asyncio
import collections
import logging
import random
import time
from . import protobufs

logger = logging.getLogger(__name__)
MSG_TYPES = protobufs.WebSocketMessage.Type


class Request(object):

    def __init__(self, wsr, verb=None, path=None, body=None, success=None,
                 error=None, id=None):
        self.wsr = wsr
        self.verb = verb
        self.path = path
        self.body = body
        self.success = success
        self.error = error
        if id is None:
            id = random.randint(0, 2**64)
        self.id = id


class IncomingWebSocketRequest(Request):

    async def respond(self, status, message):
        pbmsg = protobufs.WebSocketMessage()
        pbmsg.type = MSG_TYPES.RESPONSE
        pbmsg.response = {
            "id": self.id,
            "message": message,
            "status": status
        }
        return await self.wsr.send(pbmsg.SerializeToString())


class OutgoingWebSocketRequest(Request):

    async def send(self):
        pbmsg = protobufs.WebSocketMessage()
        pbmsg.type = MSG_TYPES.REQUEST
        pbmsg.request = {
            "verb": self.verb,
            "path": self.path,
            "body": self.body,
            "id": self.id
        }
        return await self.wsr.send(pbmsg.SerializeToString())


class WebSocketResource(object):

    def __init__(self, url, handle_request=None):
        self.url = url
        self.http = aiohttp.ClientSession()
        self.socket = None
        self._sendQueue = collections.deque()
        self._outgoingRequests = {}
        self._connectCount = 0
        self.handle_request = handle_request or self.handle_request_fallback
        self.add_event_listener('close', self.on_close.bind(self))

    async def handle_request_fallback(self, request):
        await request.respond(404, 'Not found')

    async def connect(self):
        await self.close()
        self._connectCount += 1
        if self._last_duration and self._last_duration < 120:
            delay = max(5, random.random() * self._connectCount)
            logger.warn(f'Throttling websocket reconnect for {round(delay)} seconds.')
            await asyncio.sleep(delay)
        self.socket = await self.http.ws_connect(self.url)
        self._last_connect = time.monotonic()
        while self._sendQueue:
            logger.warn("Dequeuing deferred websocket message")
            await self.socket.send_bytes(self._sendQueue.popleft())
        self._receive_task = asyncio.get_event_loop().create_task(self.receive_worker())

    async def receive_worker(self):
        socket = self.socket
        try:
            while self.socket and self.socket is socket and not self.socket.closed:
                data = await socket.recieve_bytes()
                print("DATA", data)
                await self.on_message(data)
        except:
            import pdb;pdb.set_trace()
            # how got here?  call on_close here???

    async def close(self, reason, code=3000):
        socket = self.socket
        self.socket = None
        if self._receive_task:
            self._receive_task.cancel()
            self._receive_task = None
        if socket and not self.socket:
            await socket.close(code=code, message=reason)

    async def send_request(self, options):
        request = OutgoingWebSocketRequest(self, options)
        self._outgoingRequests[request.id] = request
        await request.send()
        return request

    async def send(self, data):
        if self.socket and not self.socket.closed:
            await self.socket.send_bytes(data)
        else:
            self._sendQueue.append(data)

    async def on_message(self, encodedMsg):
        message = protobufs.WebSocketMessage()
        message.ParseFromString(encodedMsg.data)
        if message.type == MSG_TYPES.REQUEST:
            await self.handle_request(IncomingWebSocketRequest(self,
                verb=message.request.verb, path=message.request.path,
                body=message.request.body, id=message.request.id))
        elif message.type == MSG_TYPES.RESPONSE:
            response = message.response
            key = response.id
            if key in self._outgoingRequests:
                request = self._outgoingRequests[key]
                del self._outgoingRequests[key]
                request.response = response
                callback = None
                if response.status >= 200 and response.status < 300:
                    callback = request.success
                else:
                    callback = request.error
                if callback:
                    await callback(response.message, response.status, request)
            else:
                logger.error('Unmatched websocket response', key, message,
                             encodedMsg)
                raise ReferenceError('Unmatched WebSocket Response')
        else:
            raise TypeError(f'Unhandled message type: {message.type}')

    def on_close(self, code, reason):
        self._last_duration = time.monotonic() - self._last_connect
        self.socket = None
