/*
 * vim: ts=4:sw=4:expandtab
 */

'use strict';

const libsignal = require('libsignal');


module.exports = {

    // Decrypts message into a raw string
    decryptWebsocketMessage: function(message, signaling_key) {
        if (signaling_key.byteLength != 52) {
            throw new Error("Got invalid length signaling_key");
        }
        if (message.byteLength < 1 + 16 + 10) {
            throw new Error("Got invalid length message");
        }
        if (message[0] != 1) {
            throw new Error("Got bad version number: " + message[0]);
        }
        var aes_key = signaling_key.slice(0, 32);
        var mac_key = signaling_key.slice(32, 32 + 20);
        var iv = message.slice(1, 17);
        var ciphertext = message.slice(1 + 16, message.byteLength - 10);
        var ivAndCiphertext = message.slice(0, message.byteLength - 10);
        var mac = message.slice(message.byteLength - 10, message.byteLength);
        libsignal.crypto.verifyMAC(ivAndCiphertext, mac_key, mac, 10);
        return libsignal.crypto.decrypt(aes_key, ciphertext, iv);
    },

    decryptAttachment: function(encryptedBin, keys) {
        if (keys.byteLength != 64) {
            throw new Error("Got invalid length attachment keys");
        }
        if (encryptedBin.byteLength < 16 + 32) {
            throw new Error("Got invalid length attachment");
        }
        var aes_key = keys.slice(0, 32);
        var mac_key = keys.slice(32, 64);
        var iv = encryptedBin.slice(0, 16);
        var ciphertext = encryptedBin.slice(16, encryptedBin.byteLength - 32);
        var ivAndCiphertext = encryptedBin.slice(0, encryptedBin.byteLength - 32);
        var mac = encryptedBin.slice(encryptedBin.byteLength - 32, encryptedBin.byteLength);
        libsignal.crypto.verifyMAC(ivAndCiphertext, mac_key, mac, 32);
        return libsignal.crypto.decrypt(aes_key, ciphertext, iv);
    },

    encryptAttachment: function(plaintext, keys, iv) {
        if (keys.byteLength != 64) {
            throw new Error("Got invalid length attachment keys");
        }
        if (iv.byteLength != 16) {
            throw new Error("Got invalid length attachment iv");
        }
        const aes_key = keys.slice(0, 32);
        const mac_key = keys.slice(32, 64);
        const ciphertext = libsignal.crypto.encrypt(aes_key, plaintext, iv);
        const ivAndCiphertext = Buffer.concat([iv, ciphertext]);
        const mac = libsignal.crypto.sign(mac_key, ivAndCiphertext);
        return Buffer.concat([ivAndCiphertext, mac]);
    }
};
