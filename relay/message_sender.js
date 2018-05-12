// vim: ts=4:sw=4:expandtab


const Attachment = require('./attachment');
const OutgoingMessage = require('./outgoing_message');
const crypto = require('./crypto');
const errors = require('./errors');
const eventing = require('./eventing');
const hub = require('./hub');
const libsignal = require('libsignal');
const node_crypto = require('crypto');
const protobufs = require('./protobufs');
const queueAsync = require('./queue_async');
const storage = require('./storage');
const uuid4 = require('uuid/v4');

class Message {

    constructor(options) {
        Object.assign(this, options);
        if (typeof this.timestamp !== 'number') {
            throw new Error('Invalid timestamp');
        }
        if (this.expiration !== undefined && this.expiration !== null) {
            if (typeof this.expiration !== 'number' || !(this.expiration >= 0)) {
                throw new Error('Invalid expiration');
            }
        }
        if (this.attachments) {
            if (!(this.attachments instanceof Array)) {
                throw new Error('Invalid message attachments');
            }
        }
        if (this.flags !== undefined && typeof this.flags !== 'number') {
            throw new Error('Invalid message flags');
        }
    }

    isEndSession() {
        return (this.flags & protobufs.DataMessage.Flags.END_SESSION);
    }

    toProto() {
        const dataMessage = protobufs.DataMessage.create();
        if (this.body) {
            dataMessage.body = JSON.stringify(this.body);
        }
        if (this.attachmentPointers && this.attachmentPointers.length) {
            dataMessage.attachments = this.attachmentPointers;
        }
        if (this.flags) {
            dataMessage.flags = this.flags;
        }
        if (this.expiration) {
            dataMessage.expireTimer = this.expiration;
        }
        //return protobufs.Content.encode(protobufs.Content.create({dataMessage})).finish();
        return protobufs.Content.create({dataMessage});
    }
}


class MessageSender extends eventing.EventTarget {

    constructor({addr, signal, atlas}) {
        super();
        this.addr = addr;
        this.signal = signal;
        this.atlas = atlas;
    }

    static async factory() {
        const addr = await storage.getState('addr');
        const signal = await hub.SignalClient.factory();
        const atlas = await hub.AtlasClient.factory();
        return new this({addr, signal, atlas});
    }

    async makeAttachmentPointer(attachment) {
        if (!(attachment instanceof Attachment)) {
            throw TypeError("Expected `Attachment` type");
        }
        const key = node_crypto.randomBytes(64);
        const ptr = protobufs.AttachmentPointer.create({
            key,
            contentType: attachment.type
        });
        const iv = node_crypto.randomBytes(16);
        const encryptedBin = await crypto.encryptAttachment(attachment.buffer, key, iv);
        ptr.id = await this.signal.putAttachment(encryptedBin);
        return ptr;
    }

    async uploadAttachments(message) {
        const attachments = message.attachments;
        if (!attachments || !attachments.length) {
            message.attachmentPointers = [];
            return;
        }
        const uploads = attachments.map(x => this.makeAttachmentPointer(x));
        try {
            message.attachmentPointers = await Promise.all(uploads);
        } catch(e) {
            if (e instanceof errors.ProtocolError) {
                throw new errors.MessageError(message, e);
            } else {
                throw e;
            }
        }
    }

    async send({
        to=null, distribution=null,
        text=null, html=null, body=[],
        data={},
        threadId=uuid4(),
        threadType='conversation',
        threadTitle=undefined,
        messageType='content',
        messageId=uuid4(),
        messageRef=undefined,
        expiration=undefined,
        attachments=undefined,
        flags=undefined,
        sendTime=new Date(),
        userAgent='librelay'
    }) {
        if (!distribution) {
            if (!to) {
                throw TypeError("`to` or `distribution` required");
            }
            distribution = await this.atlas.resolveTags(to);
        }
        if (text) {
            body.push({
                type: 'text/plain',
                value: text
            });
        }
        if (html) {
            body.push({
                type: 'text/html',
                value: html
            });
        }
        if (body.length) {
            data.body = body;
        }
        if (attachments && attachments.length) {
            data.attachments = attachments.map(x => x.getMeta());
        }
        const timestamp = sendTime.getTime();
        const msg = new Message({
            addrs: distribution.userids,
            threadId,
            body: [{
                version: 1,
                threadId,
                threadType,
                messageId,
                messageType,
                messageRef,
                distribution: {
                    expression: distribution.universal
                },
                sender: {
                    userId: this.addr
                },
                sendTime: sendTime.toISOString(),
                userAgent,
                data
            }],
            timestamp,
            attachments,
            expiration,
            flags
        });
        await this.uploadAttachments(msg);
        const msgProto = msg.toProto();
        await this._sendSync(msgProto, timestamp, threadId, expiration && Date.now());
        return this._send(msgProto, timestamp, this.scrubSelf(distribution.userids));
    }

    _send(msgProto, timestamp, addrs) {
        console.assert(addrs instanceof Array);
        const outmsg = new OutgoingMessage(this.signal, timestamp, msgProto);
        outmsg.on('keychange', this.onKeyChange.bind(this));
        for (const addr of addrs) {
            queueAsync('message-send-job-' + addr, () =>
                outmsg.sendToAddr(addr).catch(this.onError.bind(this)));
        }
        return outmsg;
    }

    async onError(e) {
        const ev = new eventing.Event('error');
        ev.error = e;
        await this.dispatchEvent(ev);
    }

    async onKeyChange(e) {
        await this.dispatchEvent(new eventing.KeyChangeEvent(e));
    }

    async _sendSync(content, timestamp, threadId, expirationStartTimestamp) {
        const sentMessage = protobufs.SyncMessage.Sent.create({
            timestamp,
            message: content.dataMessage
        });
        if (threadId) {
            sentMessage.destination = threadId;
        }
        if (expirationStartTimestamp) {
            sentMessage.expirationStartTimestamp = expirationStartTimestamp;
        }
        const syncMessage = protobufs.SyncMessage.create({sent: sentMessage});
        const syncContent = protobufs.Content.create({syncMessage});
        return this._send(syncContent, timestamp, [this.addr]);
    }

    async syncReadMessages(reads) {
        if (!reads.length) {
            console.warn("No reads to sync");
        }
        const read = reads.map(r => protobufs.SyncMessage.Read.create({
            timestamp: r.timestamp,
            sender: r.sender
        }));
        const syncMessage = protobufs.SyncMessage.create({read});
        const content = protobufs.Content.create({syncMessage});
        return this._send(content, Date.now(), [this.addr]);
    }

    scrubSelf(addrs) {
        const nset = new Set(addrs);
        nset.delete(this.addr);
        return Array.from(nset);
    }

    async closeSession(addr, timestamp=Date.now()) {
        const dataMessage = protobufs.DataMessage.create({
            flags: protobufs.DataMessage.Flags.END_SESSION
        });
        const content = protobufs.Content.create({dataMessage});
        const outmsg = this._send(content, timestamp, [addr]);
        const deviceIds = await storage.getDeviceIds(addr);
        await new Promise(resolve => {
            outmsg.on('sent', resolve);
            outmsg.on('error', resolve);
        });
        await Promise.all(deviceIds.map(deviceId => {
            const address = new libsignal.SignalProtocolAddress(addr, deviceId);
            const sessionCipher = new libsignal.SessionCipher(storage, address);
            return sessionCipher.closeOpenSessionForDevice();
        }));
    }
}

module.exports = MessageSender;
