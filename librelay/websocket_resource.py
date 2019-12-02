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
        self._sendQueue = asyncio.Queue()
        self._closeRequest = asyncio.Future()
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
                logger.warning('Throttling websocket reconnect for '
                               f'{round(delay)} seconds.')
                await asyncio.sleep(delay)
        self._connectCount += 1
        self._lastConnect = time.monotonic()
        assert not self._ioTask
        self._ioTask = asyncio.create_task(self.ioLoop())

    async def ioLoop(self):
        """ This is overly complicated because aiohttp requires send and recv
        to be in the same task. """
        recvTask = None
        sendTask = None
        closeRequest = self._closeRequest
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=900)) as s:
            async with s.ws_connect(self.url, heartbeat=self._heartbeat) as ws:
                while True:
                    if recvTask is None:
                        recvTask = asyncio.create_task(ws.receive())
                    if sendTask is None:
                        sendTask = asyncio.create_task(self._sendQueue.get())
                    done, pending = await asyncio.wait({recvTask, sendTask, closeRequest},
                                                       return_when=asyncio.FIRST_COMPLETED)
                    if closeRequest in done:
                        code, reason = await closeRequest
                        await ws.close(code=code, reason=reason)
                        break
                    if recvTask in done:
                        msg = await recvTask
                        recvTask = None
                        if msg.type == aiohttp.WSMsgType.BINARY:
                            await self.messageHandler(msg.data)
                        elif msg.type == aiohttp.WSMsgType.CLOSED:
                            await self.close(msg.data, msg.extra)
                        else:
                            logger.error("Unhandled websocket message: %s" % (msg,))
                    if sendTask in done:
                        data = await sendTask
                        sendTask = None
                        while True:
                            await ws.send_bytes(data)
                            try:
                                data = self._sendQueue.get_nowait()
                            except asyncio.QueueEmpty:
                                break

    async def close(self, code=3000, reason=None):
        self._closeRequest.set_result((code, reason))
        self._closeRequest = asyncio.Future()
        assert self._ioTask
        await self._ioTask
        self._ioTask = None
        if self._lastConnect:
            self._lastDuration = time.monotonic() - self._lastConnect
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
            await self._handleRequest(IncomingWebSocketRequest(
                self,
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
