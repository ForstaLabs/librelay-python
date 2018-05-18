"""
Forsta message sending interface.
"""

import asyncio
import datetime
import json
import logging
import secrets
import uuid
from . import crypto, eventing, hub, storage
from . import protobufs
from .attachment import Attachment
from .outgoing_message import OutgoingMessage
from .queue_async import queue_async

store = storage.getStore()
logger = logging.getLogger(__name__)


def jsNow():
    """ Epoch in ms like javascript. """
    return round(datetime.datetime.now().timestamp() * 1000)


class Message(object):
    """ XXX This is a silly interface right now..  prove your worth! """

    def __init__(self, **options):
        self.__dict__.update(options)  # XXX ick.. 

    def isEndSession(self):
        return self.flags & protobufs.DataMessage.END_SESSION

    def toProto(self):
        content = protobufs.Content()
        #dataMessage = protobufs.DataMessage()
        dataMessage = content.dataMessage
        if self.body:
            dataMessage.body = json.dumps(self.body)
        if self.attachmentPointers:
            dataMessage.attachments = self.attachmentPointers
        if self.flags:
            dataMessage.flags = self.flags
        if self.expiration:
            dataMessage.expireTimer = self.expiration
        #content = protobufs.Content()
        #content.dataMessage = dataMessage
        return content


class MessageSender(eventing.EventTarget):

    def __init__(self, addr, signal, atlas):
        self.addr = addr
        self.signal = signal
        self.atlas = atlas

    @classmethod
    def factory(cls):
        addr = storage.getState('addr')
        signal = hub.SignalClient.factory()
        atlas = hub.AtlasClient.factory()
        return cls(addr, signal, atlas)

    async def makeAttachmentPointer(self, attachment):
        assert isinstance(attachment, Attachment)
        key = secrets.token_bytes(64)
        ptr = protobufs.AttachmentPointer()
        ptr.key = key
        ptr.contentType = attachment.type
        iv = secrets.token_bytes(16);
        encrypted = crypto.encryptAttachment(attachment.serialize(), key, iv)
        ptr.id = await self.signal.putAttachment(encrypted)
        return ptr

    async def uploadAttachments(self, message):
        attachments = message.attachments;
        import pdb;pdb.set_trace()   # I don't think we need to do this patch job with python
        if not attachments:
            message.attachmentPointers = []
            return
        uploads = map(attachments, self.makeAttachmentPointer)
        message.attachmentPointers = await asyncio.gather(uploads)

    async def send(self,
        to=None, distribution=None,
        text=None, html=None, body=None,
        data=None,
        threadId=None,
        threadType='conversation',
        threadTitle=None,
        messageType='content',
        messageId=None,
        messageRef=None,
        expiration=None,
        attachments=None,
        flags=None,
        sendTime=datetime.datetime.now(),
        userAgent='librelay-python'):
        if data is None:
            data = {}
        if threadId is None:
            threadId = uuid.uuid4()
        if messageId is None:
            messageId = uuid.uuid4()
        if distribution is None:
            if to is None:
                raise TypeError("`to` or `distribution` required")
            distribution = await self.atlas.resolveTags(to)
        if body is None:
            body = []
        if text:
            body.append({
                "type": 'text/plain',
                "value": text
            })
        if html:
            body.append({
                "type": 'text/html',
                "value": html
            })
        if body:
            data['body'] = body
        if attachments:
            data['attachments'] = [x.getMeta() for x in attachments]
        timestamp = jsNow()
        msg = Message(
            addrs=distribution['userids'],
            threadId=threadId,
            body=[{
                "version": 1,
                "threadId": threadId,
                "threadType": threadType,
                "messageId": messageId,
                "messageType": messageType,
                "messageRef": messageRef,
                "distribution": {
                    "expression": distribution['universal']
                },
                "sender": {
                    "userId": self.addr
                },
                "sendTime": sendTime.isoformat(),
                "userAgent": userAgent,
                "data": data
            }],
            timestamp = timestamp,
            attachments = attachments,
            expiration = expiration,
            flags = flags)
        await self.uploadAttachments(msg)
        msgProto = msg.toProto()
        await self._sendSync(msgProto, timestamp, threadId,
                             expiration and timestamp)
        return await self._send(msgProto, timestamp,
                                self.scrubSelf(distribution['userids']))

    async def _send(self, msgProto, timestamp, addrs):
        outmsg = OutgoingMessage(self.signal, timestamp, msgProto)
        outmsg.on('keychange', self.onKeyChange)

        async def sendWrap(addr):
            try:
                await outmsg.sendToAddr(addr)
            except Exception as e:
                logger.exception("Message send error to: %s" % (addr,))
                self.onError(e)
        await asyncio.gather([queue_async(f'msg_send-{x}', lambda: sendWrap(x))
                              for x in addrs])
        return outmsg

    async def onError(self, e):
        ev = eventing.Event('error')
        ev.error = e
        await self.dispatchEvent(ev)

    async def onKeyChange(self, e):
        await self.dispatchEvent(eventing.KeyChangeEvent(e))

    async def _sendSync(self, content, timestamp, threadId,
                        expirationStartTimestamp):
        sentMessage = protobufs.SyncMessage.Sent()
        sentMessage.timestamp = timestamp
        sentMessage.message = content.dataMessage
        if threadId:
            sentMessage.destination = threadId
        if expirationStartTimestamp:
            sentMessage.expirationStartTimestamp = expirationStartTimestamp
        syncMessage = protobufs.SyncMessage()
        syncMessage.sent = sentMessage
        syncContent = protobufs.Content()
        syncContent.syncMessage = syncMessage
        return await self._send(syncContent, timestamp, [self.addr])

    async def syncReadMessages(self, reads):
        if not reads:
            logger.warning("No reads to sync")
        readProtobufs = []
        for x in reads:
            buf = protobufs.SyncMessage.Read()
            buf.timestamp = x.timestamp
            buf.sender = x.sender
            readProtobufs.append(buf)
        syncMessage = protobufs.SyncMessage()
        syncMessage.read = readProtobufs
        content = protobufs.Content()
        content.syncMessage = syncMessage
        return await self._send(content, jsNow(), [self.addr])

    def scrubSelf(self, addrs):
        return [x for x in addrs if x != self.addr]

    async def closeSession(self, addr, timestamp=None):
        if timestamp is None:
            timestamp = jsNow()
        dataMessage = protobufs.DataMessage()
        dataMessage.flags = protobufs.DataMessage.END_SESSION
        content = protobufs.Content()
        content.dataMessage = dataMessage
        outmsg = await self._send(content, timestamp, [addr])
        deviceIds = store.getDeviceIds(addr)
        raise NotImplementedError('xxx')
        print('XXX is async?', deviceIds)
        print('XXX is async?', deviceIds)
        print('XXX is async?', deviceIds)
        #await Promise(resolve => {
        #    outmsg.on('sent', resolve)
        #    outmsg.on('error', resolve)
        #})
        #await Promise.all(deviceIds.map(deviceId => {
        #    address = libsignal.SignalProtocolAddress(addr, deviceId)
        #    sessionCipher = libsignal.SessionCipher(storage, address)
        #    return sessionCipher.closeOpenSessionForDevice()
        #}))
