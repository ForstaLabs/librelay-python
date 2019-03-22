"""
Forsta message sending interface.
"""

import asyncio
import datetime
import logging
import secrets
import uuid
from . import crypto, eventing, hub, storage
from . import exchange
from . import protobufs
from .attachment import Attachment
from .outgoing_message import OutgoingMessage

store = storage.getStore()
logger = logging.getLogger(__name__)


def msnow():
    """ Epoch in ms like java*. """
    return round(datetime.datetime.now().timestamp() * 1000)


class MessageSender(eventing.EventTarget):

    def __init__(self, addr, signal, atlas):
        assert addr
        assert isinstance(signal, hub.SignalClient)
        assert isinstance(atlas, hub.AtlasClient)
        self.addr = addr
        self.signal = signal
        self.atlas = atlas

    @classmethod
    def factory(cls):
        addr = store.getState('addr')
        signal = hub.SignalClient.factory()
        atlas = hub.AtlasClient.factory()
        return cls(addr, signal, atlas)

    async def _makeAttachmentPointer(self, attachment):
        assert isinstance(attachment, Attachment)
        key = secrets.token_bytes(64)
        ptr = protobufs.AttachmentPointer()
        ptr.key = key
        ptr.contentType = attachment.type
        iv = secrets.token_bytes(16);
        encrypted = crypto.encryptAttachment(attachment.serialize(), key, iv)
        ptr.id = await self.signal.putAttachment(encrypted)
        return ptr

    async def send(self,
        to=None, distribution=None, addrs=None,
        text=None, html=None,
        data=None,
        threadId=None,
        threadType='conversation',
        threadTitle=None,
        messageType='content',
        messageId=None,
        messageRef=None,
        expiration=0,
        attachments=None,
        flags=0,
        userAgent='librelay-python',
        noSync=False,
        actions=None,
        actionOptions=None):
        """ Primary method for sending messages. """
        ex = exchange.create()
        if distribution is None:
            if to is not None:
                distribution = await self.atlas.resolveTags(to)
            elif not addrs:
                raise TypeError("`to`, `distribution` or `addrs` required")
        if distribution is not None:
            ex.setThreadExpression(distribution['universal'])
            if addrs is None:
                addrs = distribution['userids']
        if text is not None:
            ex.setBody(text)
        if html is not None:
            ex.setBody(html, html=True)
        ex.setThreadId(threadId)
        ex.setThreadType(threadType)
        ex.setThreadTitle(threadTitle)
        ex.setMessageType(messageType)
        if messageId is None:
            messageId = str(uuid.uuid4())
        ex.setMessageId(messageId)
        ex.setMessageRef(messageRef)
        ex.setUserAgent(userAgent)
        ex.setSource(self.addr)
        ex.setExpiration(expiration)
        ex.setFlags(flags)
        if actions:
            ex.setDataProperty('actions', actions)
            if actionOptions:
                ex.setDataProperty('actionOptions', actionOptions)
        if data:
            for k, v in data.items():
                ex.setDataProperty(k, v)
        if attachments:
            # TODO Port to exchange interfaces (TBD)
            ex.setAttachments([x.getMeta() for x in attachments])
        dataMessage = ex.encode()
        if attachments:
            # TODO Port to exchange interfaces (TBD)
            uploads = map(attachments, self._makeAttachmentPointer)
            dataMessage.attachments = await asyncio.gather(uploads)
        content = protobufs.Content(dataMessage=dataMessage)
        ts = msnow()
        outMsg = self._send(content, ts,
                            addrs if noSync else self._scrubSelf(addrs))
        if not noSync:
            syncOutMsg = self._sendSync(content, ts, threadId, expiration and msnow())
            # Relay events from out message into the normal (non-sync) out-msg.  Even
            # if this message is just for us, it makes the interface consistent.
            syncOutMsg.on('sent', lambda entry: outMsg._emitSentEntry(entry))
            syncOutMsg.on('error', lambda entry: outMsg._emitErrorEntry(entry))
        return outMsg

    def _send(self, content, timestamp, addrs):
        assert all(addrs)
        logger.debug(f"Sending to: {addrs}")
        outmsg = OutgoingMessage(self.signal, timestamp, content)
        outmsg.on('keychange', self.onKeyChange)

        async def sendWrap(addr):
            try:
                await outmsg.sendToAddr(addr)
            except Exception as e:
                logger.exception('Message send error')
                await self.onError(e)
        loop = asyncio.get_event_loop()
        for x in addrs:
            loop.create_task(sendWrap(x))
        return outmsg

    async def onError(self, e):
        ev = eventing.Event('error')
        ev.error = e
        await self.dispatchEvent(ev)

    async def onKeyChange(self, entry):
        keyChangeEvent = eventing.KeyChangeEvent(entry['key_error'])
        await self.dispatchEvent(keyChangeEvent)
        if keyChangeEvent.accepted:
            # Copy the keychange acceptance to the entry so the outgoing
            # message can proceed.
            entry['accepted'] = True

    def _sendSync(self, content, timestamp, threadId,
                  expirationStartTimestamp):
        sentMessage = protobufs.SyncMessage.Sent()
        sentMessage.timestamp = timestamp
        sentMessage.message.CopyFrom(content.dataMessage)
        if threadId:
            sentMessage.destination = threadId
        if expirationStartTimestamp:
            sentMessage.expirationStartTimestamp = expirationStartTimestamp
        syncMessage = protobufs.SyncMessage(sent=sentMessage)
        syncContent = protobufs.Content(syncMessage=syncMessage)
        return self._send(syncContent, timestamp, [self.addr])

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
        return await self._send(content, msnow(), [self.addr])

    def _scrubSelf(self, addrs):
        return [x for x in addrs if x != self.addr]

    async def closeSession(self, addr, timestamp=None):
        if timestamp is None:
            timestamp = msnow()
        dataMessage = protobufs.DataMessage()
        dataMessage.flags = protobufs.DataMessage.END_SESSION
        content = protobufs.Content()
        content.dataMessage = dataMessage
        outmsg = await self._send(content, timestamp, [addr])
        deviceIds = store.getDeviceIds(addr)
        raise NotImplementedError('xxx')
        #await Promise(resolve => {
        #    outmsg.on('sent', resolve)
        #    outmsg.on('error', resolve)
        #})
        #await Promise.all(deviceIds.map(deviceId => {
        #    address = libsignal.SignalProtocolAddress(addr, deviceId)
        #    sessionCipher = libsignal.SessionCipher(store, address)
        #    return sessionCipher.closeOpenSessionForDevice()
        #}))
