import aiohttp
import asyncio
import inspect
import logging
import random
import time
from . import eventing
from . import protobufs

logger = logging.getLogger(__name__)


class Request(object):

    def __init__(self, wsr, verb=None, path=None, body=b'', success=None,
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


class WebSocketResource(eventing.EventTarget):

    def __init__(self, url, handleRequest=None, heartbeat=30):
        self.url = url
        self._http = aiohttp.ClientSession()
        self._socket = None
        self._sendQueue = asyncio.Queue()
        self._outgoingRequests = {}
        self._connectCount = 0
        self._lastDuration = 0
        self._lastConnect = None
        self._handleRequest = handleRequest or self.handleRequestFallback
        self._heartbeat = heartbeat
        self._ioTask = None

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
        self._socket = await self._http.ws_connect(self.url,
            heartbeat=self._heartbeat)
        self._lastConnect = time.monotonic()
        loop = asyncio.get_event_loop()
        self._ioTask = loop.create_task(self.ioLoop(loop))

    async def ioLoop(self, loop):
        socket = self._socket
        while socket is self._socket:
            try:
                await self._ioLoop(socket, loop)
            except asyncio.CancelledError:
                logger.debug("Websocket ioloop cancelled")
                break
            except Exception as e:
                logger.exception("Websocket ioloop error:")
                await asyncio.sleep(1)
        logger.warn("Websocket ioloop exit")

    async def _ioLoop(self, socket, loop):
        """ This is overly complicated because aiohttp requires send and recv
        to be in the same task. """
        recvTask = None
        sendTask = None
        while socket is self._socket:
            if recvTask is None:
                recvTask = loop.create_task(self._socket.receive())
            if sendTask is None:
                sendTask = loop.create_task(self._sendQueue.get())
            done, pending = await asyncio.wait({recvTask, sendTask},
                                               return_when=asyncio.FIRST_COMPLETED)
            if recvTask in done:
                msg = await recvTask
                recvTask = None
                if msg.type == aiohttp.WSMsgType.BINARY:
                    await asyncio.shield(self.messageHandler(msg.data))
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    await asyncio.shield(self.close(msg.data, msg.extra))
                else:
                    logger.error("Unhandled websocket message: %s" % (msg,))
            if sendTask in done:
                data = await sendTask
                sendTask = None
                await self._socket.send_bytes(data)
                self._sendQueue.task_done()

    async def close(self, code=3000, reason=None):
        socket = self._socket
        self._socket = None
        if self._ioTask:
            self._ioTask.cancel()
            self._ioTask = None
        if self._lastConnect:
            self._lastDuration = time.monotonic() - self._lastConnect
        if socket:
            try:
                await socket.close(code=code, message=reason)
            finally:
                ev = eventing.Event('close')
                ev.code = code
                ev.reason = reason
                await self.dispatchEvent(ev)

    async def sendRequest(self, **kwargs):
        request = OutgoingWebSocketRequest(self, **kwargs)
        self._outgoingRequests[request.id] = request
        await request.send()
        return request

    async def send(self, data):
        await self._sendQueue.put(data)

    async def messageHandler(self, data):
        message = protobufs.WebSocketMessage()
        message.ParseFromString(data)
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
                    r = callback(response.message, response.status, request)
                    if inspect.isawaitable(r):
                        await r
            else:
                logger.error('Unmatched websocket response', key, message,
                             message.data)
                raise ReferenceError('Unmatched WebSocket Response')
        else:
            raise TypeError(f'Unhandled message type: {message.type}')
