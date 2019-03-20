"""
Device onboarding protocol
"""

from . import crypto
from . import protobufs
from libsignal.ecc.curve import Curve
from libsignal.ecc.eckeypair import ECKeyPair
from libsignal.ecc.djbec import DjbECPublicKey, DjbECPrivateKey
from libsignal.kdf.hkdf import HKDF
from libsignal.sessioncipher import AESCipher


class ProvisioningCipher(object):

    def __init__(self):
        self.keyPair = None

    async def decrypt(self, provisionEnvelope):
        masterEphemeral = Curve.decodePoint(provisionEnvelope.publicKey)
        message = provisionEnvelope.body
        if message[0] != 1:
            raise ValueError("Bad version number on ProvisioningMessage")
        iv = message[1:16 + 1]
        mac = message[-32:]
        ivAndCiphertext = message[:-32]
        ciphertext = message[16 + 1:-32]
        ecRes = Curve.calculateAgreement(masterEphemeral, self.keyPair.privateKey)
        data = HKDF.createFor(3).deriveSecrets(ecRes, b"TextSecure Provisioning Message", 64)
        keyOne, keyTwo = data[:32], data[32:]
        crypto.verifyMAC(ivAndCiphertext, keyTwo, mac)
        plaintext = AESCipher(keyOne, iv).decrypt(ciphertext)
        provisionMessage = protobufs.ProvisionMessage()
        provisionMessage.ParseFromString(plaintext)
        privateKey = provisionMessage.identityKeyPrivate
        publicKey = Curve.generatePublicKey(privateKey)
        return {
            "identityKeyPair": ECKeyPair(DjbECPublicKey(publicKey),
                                         DjbECPrivateKey(privateKey)),
            "addr": provisionMessage.addr,
            "provisioningCode": provisionMessage.provisioningCode,
            "userAgent": provisionMessage.userAgent
        }

    async def encrypt(self, theirPublicKey, message):
        ourKeyPair = Curve.generateKeyPair()
        sharedSecret = Curve.calculateAgreement(theirPublicKey,
                                                ourKeyPair.privateKey)
        '''
        derivedSecret = await libsignal.crypto.HKDF(sharedSecret, Buffer.alloc(32),
            Buffer.from("TextSecure Provisioning Message"))
        ivLen = 16
        macLen = 32
        iv = crypto.randomBytes(ivLen)
        encryptedMsg = await libsignal.crypto.encrypt(derivedSecret[0], message /* XXX validate is Buffer / right */, iv)
        msgLen = encryptedMsg.byteLength

        data = Uint8Array(1 + ivLen + msgLen)
        data[0] = 1;  // Version
        data.set(iv, 1)
        data.set(Uint8Array(encryptedMsg), 1 + ivLen)
        mac = await libsignal.crypto.calculateMAC(derivedSecret[1], data.buffer)
        pEnvelope = protobufs.ProvisionEnvelope()
        pEnvelope.body = Uint8Array(data.byteLength + macLen)
        pEnvelope.body.set(data, 0)
        pEnvelope.body.set(Uint8Array(mac), data.byteLength)
        pEnvelope.publicKey = ourKeyPair.publicKey
        return pEnvelope
        '''

    def getPublicKey(self):
        if not self.keyPair:
            self.keyPair = Curve.generateKeyPair()
        return self.keyPair.publicKey
