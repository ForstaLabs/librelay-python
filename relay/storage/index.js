// vim: ts=4:sw=4:expandtab

'use strict';

const util = require('../util');
const libsignal = require('libsignal');
const process = require('process');
exports.backing = require('./backing');

const defaultBacking = process.env.RELAY_STORAGE_BACKING || 'fs';

const stateNS = 'state';
const sessionNS = 'session';
const preKeyNS = 'prekey';
const signedPreKeyNS = 'signedprekey';
const identityKeyNS = 'identitykey';


let _backing;
let _Backing;
let _label = 'default';


function encode(data) {
    const o = {};
    if (data instanceof Buffer) {
        o.type = 'buffer';
        o.data = data.toString('base64');
    } else if (data instanceof ArrayBuffer) {
        throw TypeError("ArrayBuffer not supported");
    } else if (data instanceof Uint8Array) {
        o.type = 'uint8array';
        o.data = Buffer.from(data).toString('base64');
    } else {
        o.data = data;
    }
    return JSON.stringify(o);
}

function decode(obj) {
    const o = JSON.parse(obj);
    if (o.type) {
        if (o.type === 'buffer') {
            return Buffer.from(o.data, 'base64');
        } else if (o.type === 'uint8array') {
            return Uint8Array.from(Buffer.from(o.data, 'base64'));
        } else {
            throw TypeError("Unsupported type: " + o.type);
        }
    } else {
        return o.data;
    }
}

exports.get = async (ns, key, defaultValue) => {
    let data;
    try {
        data = await _backing.get(ns, key);
    } catch(e) {
        if (e instanceof ReferenceError) {
            return defaultValue;
        } else {
            throw e;
        }
    }
    return data && decode(data);
};
exports.initialize = () => _backing.initialize();
exports.set = (ns, key, value) => _backing.set(ns, key, encode(value));
exports.has = (ns, key, value) => _backing.has(ns, key);
exports.remove = (ns, key) => _backing.remove(ns, key);
exports.keys = (ns, re) => _backing.keys(ns, re);
exports.shutdown = () => _backing.shutdown();

exports.getState = async function(key, defaultValue) {
    return await exports.get(stateNS, key, defaultValue);
};

exports.putState = async function(key, value) {
    return await exports.set(stateNS, key, value);
};

exports.removeState = async function(key) {
    return await _backing.remove(stateNS, key);
};

exports.getOurIdentity = async function() {
    return {
        pubKey: await exports.getState('ourIdentityKey.pub'),
        privKey: await exports.getState('ourIdentityKey.priv')
    };
};

exports.saveOurIdentity = async function(keyPair) {
    await exports.putState('ourIdentityKey.pub', keyPair.pubKey);
    await exports.putState('ourIdentityKey.priv', keyPair.privKey);
};

exports.removeOurIdentity = async function() {
    await exports.removeState('ourIdentityKey.pub');
    await exports.removeState('ourIdentityKey.priv');
};

exports.getOurRegistrationId = async function() {
    return await exports.getState('registrationId');
};

exports.loadPreKey = async function(keyId) {
    if (!await _backing.has(preKeyNS, keyId + '.pub')) {
        return;
    }
    return {
        pubKey: await exports.get(preKeyNS, keyId + '.pub'),
        privKey: await exports.get(preKeyNS, keyId + '.priv')
    };
};

exports.storePreKey = async function(keyId, keyPair) {
    await exports.set(preKeyNS, keyId + '.priv', keyPair.privKey);
    await exports.set(preKeyNS, keyId + '.pub', keyPair.pubKey);
};

exports.removePreKey = async function(keyId) {
    try {
        await _backing.remove(preKeyNS, keyId + '.pub');
        await _backing.remove(preKeyNS, keyId + '.priv');
    } finally {
        // Avoid circular require..
        const hub = require('../hub');
        const signal = await hub.SignalClient.factory();
        await signal.refreshPreKeys();
    }
};

exports.loadSignedPreKey = async function(keyId) {
    if (!await _backing.has(signedPreKeyNS, keyId + '.pub')) {
        return;
    }
    return {
        pubKey: await exports.get(signedPreKeyNS, keyId + '.pub'),
        privKey: await exports.get(signedPreKeyNS, keyId + '.priv')
    };
};

exports.storeSignedPreKey = async function(keyId, keyPair) {
    await exports.set(signedPreKeyNS, keyId + '.priv', keyPair.privKey);
    await exports.set(signedPreKeyNS, keyId + '.pub', keyPair.pubKey);
};

exports.removeSignedPreKey = async function(keyId) {
    await _backing.remove(signedPreKeyNS, keyId + '.pub');
    await _backing.remove(signedPreKeyNS, keyId + '.priv');
};

exports.loadSession = async function(encodedAddr) {
    if (encodedAddr === null || encodedAddr === undefined) {
        throw new Error("Tried to get session for undefined/null addr");
    }
    const data = await exports.get(sessionNS, encodedAddr);
    if (data !== undefined) {
        return libsignal.SessionRecord.deserialize(data);
    }
};

exports.storeSession = async function(encodedAddr, record) {
    if (encodedAddr === null || encodedAddr === undefined) {
        throw new Error("Tried to set session for undefined/null addr");
    }
    await exports.set(sessionNS, encodedAddr, record.serialize());
};

exports.removeSession = async function(encodedAddr) {
    await _backing.remove(sessionNS, encodedAddr);
};

exports.removeAllSessions = async function _removeAllSessions(addr) {
    if (addr === null || addr === undefined) {
        throw new Error("Tried to remove sessions for undefined/null addr");
    }
    for (const x of await _backing.keys(sessionNS, new RegExp(addr + '\\..*'))) {
        await _backing.remove(sessionNS, x);
    }
};

exports.clearSessionStore = async function() {
    for (const x of await _backing.keys(sessionNS)) {
        await _backing.remove(sessionNS, x);
    }
};

exports.isTrustedIdentity = async function(identifier, publicKey) {
    if (identifier === null || identifier === undefined) {
        throw new Error("Tried to get identity key for undefined/null key");
    }
    const identityKey = await exports.loadIdentity(identifier);
    if (!identityKey) {
        console.warn("WARNING: Implicit trust of peer:", identifier);
        return true;
    }
    return identityKey.equals(publicKey);
};

exports.loadIdentity = async function(identifier) {
    if (!identifier) {
        throw new Error("Tried to get identity key for undefined/null key");
    }
    const addr = util.unencodeAddr(identifier)[0];
    return await exports.get(identityKeyNS, addr);
};

exports.saveIdentity = async function(identifier, publicKey) {
    /* Returns true if the key was updated */
    if (!identifier) {
        throw new Error("Tried to set identity key for undefined/null key");
    }
    if (!(publicKey instanceof Buffer)) {
        throw new Error(`Invalid type for saveIdentity: ${publicKey.constructor.name}`);
    }
    const addr = util.unencodeAddr(identifier)[0];
    const existing = await exports.get(identityKeyNS, addr);
    await exports.set(identityKeyNS, addr, publicKey);
    return !!(existing && !existing.equals(publicKey));
};

exports.removeIdentity = async function(identifier) {
    const addr = util.unencodeAddr(identifier)[0];
    await _backing.remove(identityKeyNS, addr);
    await exports.removeAllSessions(addr);
};

exports.getDeviceIds = async function(addr) {
    if (addr === null || addr === undefined) {
        throw new Error("Tried to get device ids for undefined/null addr");
    }
    const idents = await _backing.keys(sessionNS, new RegExp(addr + '\\..*'));
    return Array.from(idents).map(x => x.split('.')[1]);
};

function getBackingClass(name) {
    return {
        redis: exports.backing.RedisBacking,
        postgres: exports.backing.PostgresBacking,
        fs: exports.backing.FSBacking
    }[name];
}

exports.setBacking = function(Backing) {
    if (typeof Backing === 'string') {
        Backing = getBackingClass(Backing);
    }
    if (!Backing) {
        throw new TypeError("Invalid storage backing: " + Backing);
    }
    _Backing = Backing;
    _backing = new Backing(_label);
};

exports.setLabel = function(label) {
    _label = label;
    _backing = new _Backing(label);
};


exports.setBacking(defaultBacking);
