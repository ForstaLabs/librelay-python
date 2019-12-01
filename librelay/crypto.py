import hashlib
import hmac
import logging
from . import executor
from libsignal.sessioncipher import AESCipher

logger = logging.getLogger(__name__)


async def sign(*args):
    return await executor.run(_sign, *args)


def _sign(key, data):
    m = hmac.new(key, digestmod=hashlib.sha256)
    m.update(data)
    return m.digest()


async def verifyMAC(*args):
    return await executor.run(_verifyMAC, *args)


def _verifyMAC(data, key, mac):
    calculated_mac = _sign(key, data)
    length = len(mac)
    if mac != calculated_mac[:length]:
        raise Exception("Bad MAC")


async def decryptWebSocketMessage(*args):
    return await executor.run(_decryptWebSocketMessage, *args)


def _decryptWebSocketMessage(message, signaling_key):
    """ Decrypts message into a raw string """
    if len(signaling_key) != 52:
        raise ValueError("Got invalid length signaling_key")
    if len(message) < 1 + 16 + 10:
        raise ValueError("Got invalid length message")
    if message[0] != 1:
        raise ValueError("Got bad version number: " + message[0])
    aes_key = signaling_key[:32]
    mac_key = signaling_key[32:32 + 20]
    iv = message[1:17]
    ciphertext = message[1 + 16:-10]
    ivAndCiphertext = message[:-10]
    mac = message[-10:]
    _verifyMAC(ivAndCiphertext, mac_key, mac)
    return AESCipher(aes_key, iv).decrypt(ciphertext)


async def decryptAttachment(*args):
    return await executor.run(_decryptAttachment, *args)


def _decryptAttachment(encryptedBin, keys):
    if len(keys) != 64:
        raise ValueError("Got invalid length attachment keys")
    if len(encryptedBin) < 16 + 32:
        raise ValueError("Got invalid length attachment")
    aes_key = keys[:32]
    mac_key = keys[32:64]
    iv = encryptedBin[:16]
    ciphertext = encryptedBin[16:-32]
    ivAndCiphertext = encryptedBin[:-32]
    mac = encryptedBin[-32:]
    _verifyMAC(ivAndCiphertext, mac_key, mac)
    return AESCipher(aes_key, iv).decrypt(ciphertext)


async def encryptAttachment(*args):
    return await executor.run(_encryptAttachment, *args)


def _encryptAttachment(plaintext, keys, iv):
    if len(keys) != 64:
        raise ValueError("Got invalid length attachment keys")
    if len(iv) != 16:
        raise ValueError("Got invalid length attachment iv")
    aes_key = keys[:32]
    mac_key = keys[32:64]
    ciphertext = AESCipher(aes_key, iv).encrypt(plaintext)
    ivAndCiphertext = iv + ciphertext
    mac = _sign(mac_key, ivAndCiphertext)
    return ivAndCiphertext + mac
