#WebSocketResource = require('./websocket_resource');
from . import crypto
errors = require('./errors');
eventing = require('./eventing');
hub = require('./hub');
libsignal = require('libsignal');
protobufs = require('./protobufs');
queueAsync = require('./queue_async');
storage = require('./storage');


ENV_TYPES = protobufs.Envelope.lookup('Type').values;
DATA_FLAGS = protobufs.DataMessage.lookup('Flags').values;


class MessageReceiver extends eventing.EventTarget {

    constructor(signal, addr, deviceId, signalingKey, noWebSocket) {
        super();
        console.assert(signal && addr && deviceId && signalingKey);
        this.signal = signal;
        this.addr = addr;
        this.deviceId = deviceId;
        this.signalingKey = signalingKey;
        if (!noWebSocket) {
            url = this.signal.getMessageWebSocketURL();
            this.wsr = new WebSocketResource(url, {
                handleRequest: request => queueAsync(this, this.handleRequest.bind(this, request)),
                keepalive: {
                    path: '/v1/keepalive',
                    disconnect: true
                }
            });
            this.wsr.addEventListener('close', this.onSocketClose.bind(this));
            this.wsr.addEventListener('error', this.onSocketError.bind(this));
        }
    }

    static async factory(noWebSocket) {
        signal = await hub.SignalClient.factory();
        addr = await storage.getState('addr');
        deviceId = await storage.getState('deviceId');
        signalingKey = await storage.getState('signalingKey');
        return new this(signal, addr, deviceId, signalingKey, noWebSocket);
    }

    async checkRegistration() {
        try {
            // possible auth or network issue. Make a request to confirm
            await this.signal.getDevices();
        } catch(e) {
            console.error("Invalid network state:", e);
            ev = new eventing.Event('error');
            ev.error = e;
            await this.dispatchEvent(ev);
        }
    }

    async connect() {
        if (this._closing) {
            throw new Error("Invalid State: Already Closed");
        }
        if (this._connecting) {
            console.warn("Duplicate connect detected");
        } else {
            this._connecting = (async () => {
                attempts = 0;
                while (!this._closing) {
                    try {
                        await this.wsr.connect();
                        if (attempts) {
                            console.info("Reconnected websocket");
                        }
                        return;
                    } catch(e) {
                        await this.checkRegistration();
                        console.warn(`Connect problem (${attempts++} attempts)`);
                    }
                }
            })();
        }
        await this._connecting;
        this._connecting = null;
    }

    close() {
        this._closing = true;
        this.wsr.close();
    }

    async drain() {
        /* Pop messages directly from the messages API until it's empty. */
        if (this.wsr) {
            throw new TypeError("Fetch is invalid when websocket is in use");
        }
        more = None
        do {
            data = await this.signal.request({call: 'messages'});
            more = data.more;
            deleting = [];
            for (envelope of data.messages) {
                if (envelope.content) {
                    envelope.content = Buffer.from(envelope.content, 'base64');
                }
                if (envelope.message) {
                    envelope.legacyMessage = Buffer.from(envelope.message, 'base64');
                }
                await this.handleEnvelope(envelope);
                deleting.push(this.signal.request({
                    call: 'messages',
                    httpType: 'DELETE',
                    urlParameters: `/${envelope.source}/${envelope.timestamp}`
                }));
            }
            await Promise.all(deleting);
        } while(more);
    }

    onSocketError(ev) {
        console.warn('Message Receiver WebSocket error:', ev);
    }

    async onSocketClose(ev) {
        if (this._closing) {
            return;
        }
        console.warn('Websocket closed:', ev.code, ev.reason || '');
        await this.checkRegistration();
        if (!this._closing) {
            await this.connect();
        }
    }

    async handleRequest(request) {
        if (request.path === '/api/v1/queue/empty') {
            console.debug("WebSocket queue empty");
            request.respond(200, 'OK');
            return;
        } else if (request.path !== '/api/v1/message' || request.verb !== 'PUT') {
            console.error("Expected PUT /message instead of:", request);
            request.respond(400, 'Invalid Resource');
            throw new Error('Invalid WebSocket resource received');
        }
        envelope = None
        try {
            data = crypto.decryptWebsocketMessage(Buffer.from(request.body),
                                                        this.signalingKey);
            envelope = protobufs.Envelope.toObject(protobufs.Envelope.decode(data));
            envelope.timestamp = envelope.timestamp.toNumber();
        } catch(e) {
            console.error("Error handling incoming message:", e);
            request.respond(500, 'Bad encrypted websocket message');
            ev = new eventing.Event('error');
            ev.error = e;
            await this.dispatchEvent(ev);
            throw e;
        }
        try {
            await this.handleEnvelope(envelope);
        } finally {
            request.respond(200, 'OK');
        }
    }

    async handleEnvelope(envelope, reentrant) {
        handler = None
        if (envelope.type === ENV_TYPES.RECEIPT) {
            handler = this.handleDeliveryReceipt;
        } else if (envelope.content) {
            handler = this.handleContentMessage;
        } else if (envelope.legacyMessage) {
            handler = this.handleLegacyMessage;
        } else {
            throw new Error('Received message with no content and no legacyMessage');
        }
        try {
            await handler.call(this, envelope);
        } catch(e) {
            if (e.name === 'MessageCounterError') {
                console.warn("Ignoring MessageCounterError for:", envelope);
                return;
            } else if (e instanceof errors.IncomingIdentityKeyError && !reentrant) {
                await this.dispatchEvent(new eventing.KeyChangeEvent(e));
                if (e.accepted) {
                    envelope.keyChange = true;
                    return await this.handleEnvelope(envelope, /*reentrant*/ true);
                }
            } else if (e instanceof errors.RelayError) {
                console.warn("Supressing RelayError:", e);
            } else {
                ev = new eventing.Event('error');
                ev.error = e;
                ev.proto = envelope;
                await this.dispatchEvent(ev);
                throw e;
            }
        }
    }

    async handleDeliveryReceipt(envelope) {
        ev = new eventing.Event('receipt');
        ev.proto = envelope;
        await this.dispatchEvent(ev);
    }

    unpad(buf) {
        for (i = buf.byteLength - 1; i >= 0; i--) {
            if (buf[i] == 0x80) {
                return buf.slice(0, i);
            } else if (buf[i] !== 0x00) {
                throw new Error('Invalid padding');
            }
        }
        return buf; // empty
    }

    async decrypt(envelope, ciphertext) {
        addr = new libsignal.SignalProtocolAddress(envelope.source,
                                                         envelope.sourceDevice);
        sessionCipher = new libsignal.SessionCipher(storage, addr);
        if (envelope.type === ENV_TYPES.CIPHERTEXT) {
            return this.unpad(await sessionCipher.decryptWhisperMessage(ciphertext));
        } else if (envelope.type === ENV_TYPES.PREKEY_BUNDLE) {
            return await this.decryptPreKeyWhisperMessage(ciphertext, sessionCipher, addr);
        }
        throw new Error("Unknown message type");
    }

    async decryptPreKeyWhisperMessage(ciphertext, sessionCipher, address) {
        try {
            return this.unpad(await sessionCipher.decryptPreKeyWhisperMessage(ciphertext));
        } catch(e) {
            if (e.message === 'Unknown identity key') {
                throw new errors.IncomingIdentityKeyError(address.toString(), ciphertext,
                                                          e.identityKey);
            }
            throw e;
        }
    }

    async handleSentMessage(sent, envelope) {
        if (sent.message.flags & DATA_FLAGS.END_SESSION) {
            await this.handleEndSession(sent.destination);
        }
        await this.processDecrypted(sent.message, this.addr);
        ev = new eventing.Event('sent');
        ev.data = {
            source: envelope.source,
            sourceDevice: envelope.sourceDevice,
            timestamp: sent.timestamp.toNumber(),
            destination: sent.destination,
            message: sent.message
        };
        if (sent.expirationStartTimestamp) {
          ev.data.expirationStartTimestamp = sent.expirationStartTimestamp.toNumber();
        }
        await this.dispatchEvent(ev);
    }

    async handleDataMessage(message, envelope, content) {
        if (message.flags & DATA_FLAGS.END_SESSION) {
            await this.handleEndSession(envelope.source);
        }
        await this.processDecrypted(message, envelope.source);
        ev = new eventing.Event('message');
        ev.data = {
            timestamp: envelope.timestamp,
            source: envelope.source,
            sourceDevice: envelope.sourceDevice,
            message,
            keyChange: envelope.keyChange
        };
        await this.dispatchEvent(ev);
    }

    async handleLegacyMessage(envelope) {
        data = await this.decrypt(envelope, envelope.legacyMessage);
        messageProto = protobufs.DataMessage.decode(data);
        message = protobufs.DataMessage.toObject(messageProto);
        await this.handleDataMessage(message, envelope);
    }

    async handleContentMessage(envelope) {
        data = await this.decrypt(envelope, envelope.content);
        contentProto = protobufs.Content.decode(data);
        content = protobufs.Content.toObject(contentProto);
        if (content.syncMessage) {
            await this.handleSyncMessage(content.syncMessage, envelope, content);
        } else if (content.dataMessage) {
            await this.handleDataMessage(content.dataMessage, envelope, content);
        } else {
            throw new TypeError('Got content message with no dataMessage or syncMessage');
        }
    }

    async handleSyncMessage(message, envelope, content) {
        if (envelope.source !== this.addr) {
            throw new ReferenceError('Received sync message from another addr');
        }
        if (envelope.sourceDevice == this.deviceId) {
            throw new ReferenceError('Received sync message from our own device');
        }
        if (message.sent) {
            await this.handleSentMessage(message.sent, envelope);
        } else if (message.read && message.read.length) {
            await this.handleRead(message.read, envelope);
        } else if (message.contacts) {
            console.error("Deprecated contact sync message:", message, envelope, content);
            throw new TypeError('Deprecated contact sync message');
        } else if (message.groups) {
            console.error("Deprecated group sync message:", message, envelope, content);
            throw new TypeError('Deprecated group sync message');
        } else if (message.blocked) {
            this.handleBlocked(message.blocked, envelope);
        } else if (message.request) {
            console.error("Deprecated group request sync message:", message, envelope, content);
            throw new TypeError('Deprecated group request sync message');
        } else {
            console.error("Empty sync message:", message, envelope, content);
            throw new TypeError('Empty SyncMessage');
        }
    }

    async handleRead(read, envelope) {
        for (x of read) {
            ev = new eventing.Event('read');
            ev.timestamp = envelope.timestamp;
            ev.read = {
                timestamp: x.timestamp.toNumber(),
                sender: x.sender,
                source: envelope.source,
                sourceDevice: envelope.sourceDevice
            };
            await this.dispatchEvent(ev);
        }
    }

    handleBlocked(blocked) {
        throw new Error("UNSUPPORTRED");
    }

    async handleAttachment(attachment) {
        encrypted = await this.signal.getAttachment(attachment.id.toString());
        attachment.data = await crypto.decryptAttachment(encrypted, attachment.key);
    }

    tryMessageAgain(from, ciphertext) {
        address = libsignal.SignalProtocolAddress.fromString(from);
        sessionCipher = new libsignal.SessionCipher(storage, address);
        console.warn('retrying prekey whisper message');
        return this.decryptPreKeyWhisperMessage(ciphertext, sessionCipher, address).then(function(plaintext) {
            finalMessageProto = protobufs.DataMessage.decode(plaintext);
            finalMessage = protobufs.DataMessage.toObject(finalMessageProto);
            p = Promise.resolve();
            if ((finalMessage.flags & DATA_FLAGS.END_SESSION) == DATA_FLAGS.END_SESSION &&
                finalMessage.sync !== null) {
                    p = this.handleEndSession(address.getName());
            }
            return p.then(function() {
                return this.processDecrypted(finalMessage);
            }.bind(this));
        }.bind(this));
    }

    async handleEndSession(addr) {
        deviceIds = await storage.getDeviceIds(addr);
        await Promise.all(deviceIds.map(deviceId => {
            address = new libsignal.SignalProtocolAddress(addr, deviceId);
            sessionCipher = new libsignal.SessionCipher(storage, address);
            console.warn('Closing session for', addr, deviceId);
            return sessionCipher.closeOpenSessionForDevice();
        }));
    }

    async processDecrypted(msg, source) {
        // Now that its decrypted, validate the message and clean it up for consumer processing
        // Note that messages may (generally) only perform one action and we ignore remaining fields
        // after the first action.
        if (msg.flags === null) {
            msg.flags = 0;
        }
        if (msg.expireTimer === null) {
            msg.expireTimer = 0;
        }
        if (msg.flags & DATA_FLAGS.END_SESSION) {
            return msg;
        }
        if (msg.group) {
            // We should blow up here very soon. XXX
            console.error("Legacy group message detected", msg);
        }
        if (msg.attachments) {
            await Promise.all(msg.attachments.map(this.handleAttachment.bind(this)));
        }
        return msg;
    }
}


module.exports = MessageReceiver;
