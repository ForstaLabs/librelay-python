# vim: ts=4:sw=4:expandtab

import abc
import json
import logging
from . import message_receiver
from . import message_sender
from . import hub
from . import protobufs

logger = logging.getLogger(__name__)
currentVersion = 1
ExchangeClasses = {}


class Exchange(object):
    """ Interface for communicating with other Forsta devices.
        {@link https://goo.gl/eX7gyC Payload Definition} """

    def __init__(self, messageSender=None, messageReceiver=None, atlas=None,
                 signal=None):
        self._msgSender = messageSender
        self._msgReceiver = messageReceiver
        self._atlas = atlas
        self._signal = signal
        self._messageListeners = []

    async def _getMessageSender(self):
        if self._msgSender is None:
            self._msgSender = await message_sender.MessageSender.factory()
        return self._msgSender

    async def _getMessageReceiver(self):
        if self._msgReceiver is None:
            self._msgReceiver = await message_receiver.MessageReceiver.factory()
        return self._msgReceiver

    async def _getAtlasClient(self):
        if self._atlas is None:
            self._atlas = await hub.AtlasClient.factory()
        return self._atlas

    async def _getSignalClient(self):
        if self._signal is None:
            self._signal = await hub.SignalClient.factory()
        return self._signal

    def decode(self, dataMessage, payload):
        self.setExpiration(dataMessage.expireTimer)
        self.setFlags(dataMessage.flags)
        self.decodePayload(payload)

    def encode(self):
        dataMessage = protobufs.DataMessage()
        dataMessage.flags = self.getFlags()
        dataMessage.expireTimer=self.getExpiration()
        dataMessage.body = json.dumps([self.encodePayload()])
        return dataMessage

    async def send(self, onlySender=False, addrs=None, **kwargs):
        """ Send a message to self exchange's thread. """
        atlas = await self._getAtlasClient()
        distribution = await atlas.resolveTags(self.getThreadExpression())
        if addrs is None:
            addrs = [self.getSender()] if onlySender else None
        sender = await self._getMessageSender()
        return await sender.send(distribution=distribution, addrs=addrs,
                                 threadId=self.getThreadId(),
                                 threadType=self.getThreadType(),
                                 threadTitle=self.getThreadTitle(), **kwargs)

    async def _messageListener(self, ev):
        if ev.data.exchange.getThreadId() == self.getThreadId():
            for cb in self._messageListeners:
                await cb(ev)

    async def addMessageListener(self, callback):
        """ Listen for new message events on pertaining to self exchange's
        thread. """
        # Add a filtered event listener on the message receiver that only
        # fires events for message events pertaining to our thread ID.
        self._messageListeners.append(callback)
        if len(self._messageListeners) == 1:
            mr = await self._getMessageReceiver()
            mr.addEventListener('message', self._messageListener)

    async def removeMessageListener(self, callback):
        """ Remove message event listener added by addMessageListener. """
        self._messageListeners.remove(callback)
        if not self._messageListeners:
            mr = await self._getMessageReceiver()
            mr.removeEventListener('message', self._messageListener)

    def recvMessages(self, timeout=None):
        """ Generator for receiving new messages on this exchange's thread. """
        # XXX Unported, probably should be async generator instead of return Future objects
        '''
        queue = []
        waiter = None
        timeoutId = None

        def callback(ev):
            if waiter:
                if timeoutId:
                    clearTimeout(timeoutId)
                waiter(ev.data.exchange)
                waiter = null
            } else {
                queue.push(ev.data.exchange)
        self.addMessageListener(callback)
        active = true
        try {
            while (active) {
                if (queue.length) {
                    yield Promise.resolve(queue.shift())
                } else if (waiter) {
                    raise Exception("Prior promise was not awaited")
                } else {
                    yield Promise(resolve => {
                        waiter = resolve
                        if (timeout) {
                            timeoutId = setTimeout(() => {
                                active = false
                                resolve(null)
                            }, timeout)
                    })
        } finally {
            self.removeMessageListener(callback)
            if (timeoutId) {
                clearTimeout(timeoutId)
        '''
        pass

    def getExpiration(self):
        return self._expiration

    def setExpiration(self, value):
        self._expiration = value

    def getSource(self):
        """ Returns UUID for user that sent or is sending this message. """
        return self._source

    def setSource(self, value):
        """ Set the  UUID of user sending this message. """
        self._source = value

    def getSourceDevice(self):
        """ Returns device ID of source user. """
        return self._sourceDevice

    def setSourceDevice(self, value):
        """ Set the Device ID of source user for this message. """
        self._sourceDevice = value

    def getFlags(self):
        """ Signal flags associated with this message. """
        return self._flags

    def setFlags(self, value):
        """ Signal flags associated with this message. """
        self._flags = value

    def getTimestamp(self):
        """ Every message has a global and non-secret timestamp that is used to
        cross reference things like read-receipts and session retransmits. """
        return self._timestamp

    def setTimestamp(self, value):
        """ Format is epoch in milliseconds. """
        self._timestamp = value

    def getAge(self):
        """ Time self message spent waiting for delivery on the Signal server. """
        return self._age

    def setAge(self, value):
        self._age = value

    @abc.abstractmethod
    def decodePayload(self, payload):
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def encodePayload(self):
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def getBody(self, options):
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def setBody(self, value, options):
        """ Set the message body.  E.g. localized text for the message. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def getThreadExpression(self):
        """ The universal tag expression for this exchange's thread. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def setThreadExpression(self, value):
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def getThreadId(self):
        """ The UUID for this exhcange's thread. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def setThreadId(self, value):
        """ The UUID for this exhcange's thread. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def getThreadType(self):
        """ The thread type for this message. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def setThreadType(self, value):
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def getThreadTitle(self):
        """ The optional thread title. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def setThreadTitle(self, value):
        """ Localized thread title text. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def getMessageId(self):
        """" The UUID for this message. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def setMessageId(self, value):
        """" The UUID for this message. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def getMessageType(self):
        """ The message type. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def setMessageType(self, value):
        """ The message type. E.g. "content", "control", ... """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def getMessageRef(self):
        """ The optional message reference.  E.g. the UUID of a prior message
        that this message refers/replies to. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def setMessageRef(self, value):
        """ Message UUID to reference.  E.g. the replied to UUID. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def getAttachments(self):
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def setAttachments(self, value):
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def getUserAgent(self):
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def setUserAgent(self, value):
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def getDataProperty(self, key):
        """ The data key to get.  The natively typed value for this data
        property. """
        raise NotImplementedError("Subclasss impl required")

    @abc.abstractmethod
    def setDataProperty(self, key, value):
        raise NotImplementedError("Subclasss impl required")


class ExchangeV1(Exchange):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._payload = {}

    def decodePayload(self, payload):
        self._payload.update(payload)

    def encodePayload(self):
        payload = {
            "version": 1,
            "sender": {
                "userId": self.getSource()
            }
        }
        payload.update(self._payload)
        return payload

    def getBody(self, html=False):
        body = self._payload.get('data', {}).get('body')
        if not body:
            return
        entries = body
        if html:
            entries = [x for x in body if x['type'] == 'text/html']
        if not entries:
            entries = [x for x in body if x['type'] == 'text/plain']
        if not entries:
            logger.warn("Unexpected body type(s):", body)
        else:
            return entries[0]['value']

    def setBody(self, value, html=False):
        body = self.getDataProperty('body')
        if not body:
            body = []
            self.setDataProperty('body', body)
        body.append({
            "type": 'text/html' if html else 'text/plain',
            "value": value
        })

    def getSender(self):
        return self._payload.get('sender', {}).get('userId')

    def setSender(self, value):
        self._payload['sender'] = {
            "userId": value
        }

    def getThreadExpression(self):
        return self._payload.get('distribution', {}).get('expression')

    def setThreadExpression(self, value):
        if 'distribution' not in self._payload:
            self._payload['distribution'] = {}
        self._payload['distribution']['expression'] = value

    def getThreadId(self):
        return self._payload.get('threadId')

    def setThreadId(self, value):
        self._payload['threadId'] = value

    def getThreadType(self):
        return self._payload.get('threadType')

    def setThreadType(self, value):
        self._payload['threadType'] = value

    def getThreadTitle(self):
        return self._payload.get('threadTitle')

    def setThreadTitle(self, value):
        self._payload['threadTitle'] = value

    def getMessageId(self):
        return self._payload.get('messageId')

    def setMessageId(self, value):
        self._payload['messageId'] = value

    def getMessageType(self):
        return self._payload.get('messageType')

    def setMessageType(self, value):
        self._payload['messageType'] = value

    def getMessageRef(self):
        return self._payload.get('messageRef')

    def setMessageRef(self, value):
        self._payload['messageRef'] = value

    def getAttachments(self):
        return self._payload.get('attachments')

    def setAttachments(self, value):
        self._payload['attachments'] = value

    def getUserAgent(self):
        return self._payload.get('userAgent')

    def setUserAgent(self, value):
        self._payload['userAgent'] = value

    def getData(self):
        return self._payload.get('data')

    def setData(self, value):
        self._payload['data'] = value

    def getDataProperty(self, key):
        return self._payload.get('data', {}).get(key)

    def setDataProperty(self, key, value):
        if 'data' not in self._payload:
            self._payload['data'] = {}
        self._payload['data'][key] = value

ExchangeClasses[1] = ExchangeV1


def decode(dataMessage, **kwargs):
    """ Return a versioned Exchange instance based on the protocol buffer
    argument. """
    if not isinstance(dataMessage, protobufs.DataMessage):
        raise TypeError("DataMessage argument required")
    payload = json.loads(dataMessage.body)
    payload.sort(key=lambda x: x['version'], reverse=True)
    for x in payload:
        if x['version'] in ExchangeClasses:
            instance = ExchangeClasses[x['version']](**kwargs)
            instance.decode(dataMessage, x)
            return instance
    raise ReferenceError("No supported exchange versions found")


def create(**kwargs):
    """ Build a new Exchange object with our most current exchange version. """
    return ExchangeClasses[currentVersion](**kwargs)
