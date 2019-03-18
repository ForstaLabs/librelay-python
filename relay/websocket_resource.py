import aiohttp
import asyncio
import collections
import logging
import random
import time
from . import eventing
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.response = asyncio.Future()
        self._success = self.success
        self.success = self.successWrap
        self._error = self.error
        self.error = self.errorWrap

    async def successWrap(self, message, status, request):
        import pdb;pdb.set_trace()
        self.response.set_result((message, status))
        await self._success(message, status, request)

    async def errorWrap(self, message, status, request):
        self.response.set_result((message, status))
        import pdb;pdb.set_trace()
        await self._error(message, status, request)

    async def send(self):
        pbmsg = protobufs.WebSocketMessage()
        pbmsg.type = pbmsg.REQUEST
        pbmsg.request.verb = self.verb
        pbmsg.request.path = self.path
        pbmsg.request.body = self.body
        pbmsg.request.id = self.id
        return await self.wsr.send(pbmsg.SerializeToString())


class KeepAlive(object):

    interval = 45

    def __init__(self, wsr, path='/', disconnect=True):
        self.path = path
        self.disconnect = disconnect
        self.wsr = wsr
        self._tickle = asyncio.Event()
        self._stopping = None

    def start(self):
        self._stopping = False
        self._tickle.clear()
        self.wsr.addEventListener('close', self.stop)
        self._monitorTask = asyncio.get_event_loop().create_task(self.monitor())

    def stop(self):
        self._stopping = True
        self.wsr.removeEventListener('close', self.stop)
        self._monitorTask.cancel()

    def tickle(self):
        self._tickle.set()

    async def monitor(self):
        while not self._stopping:
            try:
                await asyncio.wait_for(self._tickle.wait(), self.interval)
            except asyncio.TimeoutError:
                if self.disconnect:
                    self._closeSoon = asyncio.create_task(asyncio.sleep(5))
                await self.wsr.sendRequest(verb='GET', path=self.path,
                                           success=self.onKeepalive)
            finally:
                self._tickle.clear()

    async def onKeepalive(self, message, status, request):
        print("YUP", message, status, request)
        import pdb;pdb.set_trace()
        self._closeSoon.cancel()


class WebSocketResource(eventing.EventTarget):

    def __init__(self, url, handleRequest=None, keepalive_path=None,
                 keepalive_disconnect=True):
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
        if keepalive_path:
            self.keepalive = KeepAlive(self, path=keepalive_path,
                                       disconnect=keepalive_disconnect)
        else:
            self.keepalive = None
        self.addEventListener('message', self.onMessage)
        self.addEventListener('close', self.onClose)

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
        if self.keepalive:
            self.keepalive.start()
        while self._sendQueue:
            logger.warning("Dequeuing deferred websocket message")
            await self._socket.send_bytes(self._sendQueue.popleft())
        loop = asyncio.get_event_loop()
        self._receive_task = loop.create_task(self.receiveLoop())

    async def receiveLoop(self):
        async for msg in self._socket:
            if msg.type == aiohttp.WSMsgType.BINARY:
                ev = eventing.Event('message')
                ev.data = msg.data
                await self.dispatchEvent(ev)
            elif msg.type == aiohttp.WSMsgType.CLOSED:
                import pdb;pdb.set_trace()
                ev = eventing.Event('close')
                ev.msg = msg
                await self.dispatchEvent(ev)
            elif msg.type == aiohttp.WSMsgType.ERROR:
                import pdb;pdb.set_trace()
                logger.error("WebSocket Error: %s" % (msg,))
                ev = eventing.Event('error')
                ev.msg = msg
                await self.dispatchEvent(ev)
            else:
                logger.warning("Unhandled message: %s" % (msg,))
                raise NotImplementedError(msg.type)

    async def close(self, reason=None, code=3000):
        socket = self._socket
        self._socket = None
        if self._receiveTask:
            self._receiveTask.cancel()
            self._receiveTask = None
        if self.keepalive:
            self.keepalive.stop()
        if socket and not self._socket:
            await socket.close(code=code, message=reason)

    async def sendRequest(self, **kwargs):
        request = OutgoingWebSocketRequest(self, **kwargs)
        self._outgoingRequests[request.id] = request
        await request.send()
        return request

    async def send(self, data):
        if self._socket and not self._socket.closed:
            await self._socket.send_bytes(data)
        else:
            self._sendQueue.append(data)

    async def onMessage(self, ev):
        if self.keepalive:
            self.keepalive.tickle()
        message = protobufs.WebSocketMessage()
        message.ParseFromString(ev.data)
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
                             msg.data)
                raise ReferenceError('Unmatched WebSocket Response')
        else:
            raise TypeError(f'Unhandled message type: {message.type}')

    def onClose(self, ev):
        self._lastDuration = time.monotonic() - self._lastConnect
        self._socket = None
