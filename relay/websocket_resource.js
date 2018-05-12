// vim: ts=4:sw=4:expandtab

'use strict';

const Long = require('long');
const WebSocket = require('ws');
const crypto = require('crypto');
const protobufs = require('./protobufs');
const util = require('./util');


const MSG_TYPES = protobufs.WebSocketMessage.lookup('Type').values;


class Request {
    constructor(wsr, options) {
        this.wsr = wsr;
        this.verb = options.verb || options.type;
        this.path = options.path || options.url;
        this.body = options.body || options.data;
        this.success = options.success;
        this.error = options.error;
        this.id = options.id;
        if (!this.id) {
            var ints = new Uint32Array(2);
            ints.set(crypto.randomBytes(ints.length));
            this.id = new Long(ints[0], ints[1], true /*unsigned*/);
        }
        if (this.body === undefined) {
            this.body = null;
        }
    }
}

class IncomingWebSocketRequest extends Request {
    respond(status, message) {
        const pbmsg = protobufs.WebSocketMessage.create({
            type: MSG_TYPES.RESPONSE,
            response: {
                id: this.id,
                message,
                status
            }
        });
        return this.wsr.send(protobufs.WebSocketMessage.encode(pbmsg).finish());
    }
}

class OutgoingWebSocketRequest extends Request {
    send() {
        const pbmsg = protobufs.WebSocketMessage.create({
            type: MSG_TYPES.REQUEST,
            request: {
                verb: this.verb,
                path: this.path,
                body: this.body,
                id: this.id
            }
        });
        return this.wsr.send(protobufs.WebSocketMessage.encode(pbmsg).finish());
    }
}

class KeepAlive {
    constructor(websocketResource, opts) {
        if (!(websocketResource instanceof WebSocketResource)) {
            throw new TypeError('KeepAlive expected a WebSocketResource');
        }
        opts = opts || {};
        this.path = opts.path;
        if (this.path === undefined) {
            this.path = '/';
        }
        this.disconnect = opts.disconnect;
        if (this.disconnect === undefined) {
            this.disconnect = true;
        }
        this.wsr = websocketResource;
        this._onNeedTickle = this.onNeedTickle.bind(this);
        this._onNeedClose = this.onNeedClose.bind(this);
    }

    clear() {
        clearTimeout(this.tickleTimer);
        clearTimeout(this.closeTimer);
    }

    reset() {
        this.clear();
        this.tickleTimer = setTimeout(this._onNeedTickle, 45000);
    }

    onNeedTickle() {
        this.wsr.sendRequest({
            verb: 'GET',
            path: this.path,
            success: this.reset.bind(this)
        });
        if (this.disconnect) {
            // automatically disconnect if server doesn't ack
            this.closeTimer = setTimeout(this._onNeedClose, 5000);
        }
    }

    onNeedClose() {
        clearTimeout(this.tickleTimer);
        this.wsr.close(3001, 'No response to keepalive request');
    }
}

class WebSocketResource {

    constructor(url, opts) {
        this.url = url;
        this.socket = null;
        this._sendQueue = [];
        this._outgoingRequests = new Map();
        this._listeners = [];
        this._connectCount = 0;
        opts = opts || {};
        this.handleRequest = opts.handleRequest;
        if (typeof this.handleRequest !== 'function') {
            this.handleRequest = request => request.respond(404, 'Not found');
        }
        if (opts.keepalive) {
            this.keepalive = new KeepAlive(this, {
                path: opts.keepalive.path,
                disconnect: opts.keepalive.disconnect
            });
            this.addEventListener('close', this.keepalive.clear.bind(this.keepalive));
        }
        this.addEventListener('message', this.onMessage.bind(this));
        this.addEventListener('close', this.onClose.bind(this));
    }

    addEventListener(event, callback) {
        this._listeners.push([event, callback]);
        if (this.socket) {
            this.socket.addEventListener(event, callback);
        }
    }

    removeEventListener(event, callback) {
        if (this.socket) {
            this.socket.removeEventListener(event, callback);
        }
        this._listeners = this._listeners.filter(x => !(x[0] === event && x[1] === callback));
    }

    async connect() {
        this.close();
        this._connectCount++;
        if (this._lastDuration && this._lastDuration < 10000) {
            const delay = Math.max(5, Math.random() * this._connectCount);
            console.warn(`Throttling websocket reconnect for ${Math.round(delay)} seconds.`);
            await util.sleep(delay);
        }
        const ws = new WebSocket(this.url);
        this._lastConnect = Date.now();
        await new Promise((resolve, reject) => {
            ws.addEventListener('open', resolve);
            ws.addEventListener('error', ev => {
                this._lastDuration = Date.now() - this._lastConnect;
                reject(new Error('WebSocket Connect Error'));
            });
        });
        this.socket = ws;
        for (const x of this._listeners) {
            this.socket.addEventListener(x[0], x[1]);
        }
        if (this.keepalive) {
            this.keepalive.reset();
        }
        while (this._sendQueue.length) {
            console.warn("Dequeuing deferred websocket message");
            this.socket.send(this._sendQueue.shift());
        }
    }

    close(code, reason) {
        if (this.socket && this.socket.readyState !== WebSocket.CLOSED) {
            if (!code) {
                code = 3000;
            }
            this.socket.close(code, reason);
        }
        this.socket = null;
    }

    sendRequest(options) {
        const request = new OutgoingWebSocketRequest(this, options);
        this._outgoingRequests.set(request.id.toNumber(), request);
        request.send();
        return request;
    }

    send(data) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(data);
        } else {
            this._sendQueue.push(data);
        }
    }

    async onMessage(encodedMsg) {
        if (this.keepalive) {
            this.keepalive.reset();
        }
        const messageProto = protobufs.WebSocketMessage.decode(encodedMsg.data);
        const message = protobufs.WebSocketMessage.toObject(messageProto);
        if (message.type === MSG_TYPES.REQUEST) {
            await this.handleRequest(new IncomingWebSocketRequest(this, {
                verb: message.request.verb,
                path: message.request.path,
                body: message.request.body,
                id: message.request.id
            }));
        } else if (message.type === MSG_TYPES.RESPONSE) {
            const response = message.response;
            const key = response.id.toNumber();
            if (this._outgoingRequests.has(key)) {
                const request = this._outgoingRequests.get(key);
                this._outgoingRequests.delete(key);
                request.response = response;
                let callback;
                if (response.status >= 200 && response.status < 300) {
                    callback = request.success;
                } else {
                    callback = request.error;
                }
                if (typeof callback === 'function') {
                    await callback(response.message, response.status, request);
                }
            } else {
                console.error('Unmatched websocket response', key, message, encodedMsg);
                throw ReferenceError('Unmatched WebSocket Response');
            }
        } else {
            throw new TypeError(`Unhandled message type: ${message.type}`);
        }
    }

    onClose(code, reason) {
        this._lastDuration = Date.now() - this._lastConnect;
        this.socket = null;
    }
}

module.exports = WebSocketResource;
