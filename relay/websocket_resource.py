import aiohttp
import asyncio
import collections
import logging
import random
import time
from . import protobufs

logger = logging.getLogger(__name__)


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
        pbmsg.type = pbmsg.RESPONSE
        pbmsg.response.id = self.id
        pbmsg.response.message = message
        pbmsg.response.status = status
        return await self.wsr.send(pbmsg.SerializeToString())


class OutgoingWebSocketRequest(Request):

    async def send(self):
        pbmsg = protobufs.WebSocketMessage()
        pbmsg.type = pbmsg.REQUEST
        pbmsg.request.verb = self.verb
        pbmsg.request.path = self.path
        pbmsg.request.body = self.body
        pbmsg.request.id = self.id
        return await self.wsr.send(pbmsg.SerializeToString())


class WebSocketResource(object):

    def __init__(self, url, handleRequest=None):
        self.url = url
        self._http = aiohttp.ClientSession()
        self._socket = None
        self._sendQueue = collections.deque()
        self._outgoingRequests = {}
        self._connectCount = 0
        self._lastDuration = 0
        self._lastConnect = None
        self._handleRequest = handleRequest or self.handleRequestFallback
        self._receiveTask = None

    async def handleRequestFallback(self, request):
        await request.respond(404, 'Not found')

    async def connect(self):
        if self._connectCount:
            await self.close()
            if self._lastDuration < 120:
                delay = max(5, random.random() * self._connectCount)
                logger.warning('Throttling websocket reconnect for ' \
                               f'{round(delay)} seconds.')
                await asyncio.sleep(delay)
        self._connectCount += 1
        self._socket = await self._http.ws_connect(self.url)
        self._lastConnect = time.monotonic()
        while self._sendQueue:
            logger.warning("Dequeuing deferred websocket message")
            await self._socket.send_bytes(self._sendQueue.popleft())
        loop = asyncio.get_event_loop()
        self._receive_task = loop.create_task(self.receiveLoop())

    async def receiveLoop(self):
        async for msg in self._socket:
            if msg.type == aiohttp.WSMsgType.BINARY:
                try:
                    await self.onMessage(msg.data)
                except Exception:
                    logger.exception("WebSocket onMessage error")
            elif msg.type == aiohttp.WSMsgType.CLOSED:
                import pdb;pdb.set_trace()
                await self.onClose()
            elif msg.type == aiohttp.WSMsgType.ERROR:
                logger.error("WebSocket Error:" + msg)
                import pdb;pdb.set_trace()
            else:
                logger.warning("Unhandled message: %s" % (msg,))
                raise NotImplementedError(msg.type)

    async def close(self, reason=None, code=3000):
        socket = self._socket
        self._socket = None
        if self._receiveTask:
            self._receiveTask.cancel()
            self._receiveTask = None
        if socket and not self._socket:
            await socket.close(code=code, message=reason)

    async def sendRequest(self, options):
        request = OutgoingWebSocketRequest(self, options)
        self._outgoingRequests[request.id] = request
        await request.send()
        return request

    async def send(self, data):
        if self._socket and not self._socket.closed:
            await self._socket.send_bytes(data)
        else:
            self._sendQueue.append(data)

    async def onMessage(self, encodedMsg):
        message = protobufs.WebSocketMessage()
        message.ParseFromString(encodedMsg)
        if message.type == message.REQUEST:
            await self._handleRequest(IncomingWebSocketRequest(self,
                verb=message.request.verb, path=message.request.path,
                body=message.request.body, id=message.request.id))
        elif message.type == message.RESPONSE:
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

    def onClose(self, code, reason):
        self._lastDuration = time.monotonic() - self._lastConnect
        self._socket = None
