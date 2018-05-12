// vim: ts=4:sw=4:expandtab

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const libsignal = require('libsignal');
const protobufs = require('./protobufs');


class ProvisioningCipher {

    async decrypt(provisionEnvelope) {
        const masterEphemeral = provisionEnvelope.publicKey;
        const message = provisionEnvelope.body;
        if (message[0] !== 1) {
            throw new Error("Bad version number on ProvisioningMessage");
        }
        const iv = message.slice(1, 16 + 1);
        const mac = message.slice(message.byteLength - 32, message.byteLength);
        const ivAndCiphertext = message.slice(0, message.byteLength - 32);
        const ciphertext = message.slice(16 + 1, message.byteLength - 32);
        const ecRes = libsignal.crypto.calculateAgreement(masterEphemeral, this.keyPair.privKey);
        const keys = await libsignal.crypto.HKDF(ecRes, Buffer.alloc(32),
            Buffer.from("TextSecure Provisioning Message"));
        await libsignal.crypto.verifyMAC(ivAndCiphertext, keys[1], mac, 32);
        const plaintext = await libsignal.crypto.decrypt(keys[0], ciphertext, iv);
        const provisionMessage = protobufs.ProvisionMessage.decode(plaintext);
        const privKey = provisionMessage.identityKeyPrivate;
        return {
            identityKeyPair: libsignal.crypto.createKeyPair(privKey),
            addr: provisionMessage.addr,
            provisioningCode: provisionMessage.provisioningCode,
            userAgent: provisionMessage.userAgent
        };
    }

    async encrypt(theirPublicKey, message) {
        assert(theirPublicKey instanceof Buffer);
        const ourKeyPair = libsignal.crypto.generateKeyPair();
        const sharedSecret = libsignal.crypto.calculateAgreement(theirPublicKey,
                                                                 ourKeyPair.privKey);
        const derivedSecret = await libsignal.crypto.HKDF(sharedSecret, Buffer.alloc(32),
            Buffer.from("TextSecure Provisioning Message"));
        const ivLen = 16;
        const macLen = 32;
        const iv = crypto.randomBytes(ivLen);
        const encryptedMsg = await libsignal.crypto.encrypt(derivedSecret[0], message /* XXX validate is Buffer / right */, iv);
        const msgLen = encryptedMsg.byteLength;

        const data = new Uint8Array(1 + ivLen + msgLen);
        data[0] = 1;  // Version
        data.set(iv, 1);
        data.set(new Uint8Array(encryptedMsg), 1 + ivLen);
        const mac = await libsignal.crypto.calculateMAC(derivedSecret[1], data.buffer);
        const pEnvelope = new protobufs.ProvisionEnvelope();
        pEnvelope.body = new Uint8Array(data.byteLength + macLen);
        pEnvelope.body.set(data, 0);
        pEnvelope.body.set(new Uint8Array(mac), data.byteLength);
        pEnvelope.publicKey = ourKeyPair.pubKey;
        return pEnvelope;
    }

    getPublicKey() {
        if (!this.keyPair) {
            this.keyPair = libsignal.crypto.generateKeyPair();
        }
        return this.keyPair.pubKey;
    }
}

module.exports = ProvisioningCipher;
