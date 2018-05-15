"""
Device onboarding protocol
"""

from . import protobufs
from axolotl.ecc.curve import Curve
from axolotl.ecc.eckeypair import ECKeyPair
from axolotl.ecc.djbec import DjbECPublicKey, DjbECPrivateKey
from axolotl.kdf.hkdf import HKDF
from axolotl.protocol.whispermessage import WhisperMessage
from axolotl.sessioncipher import AESCipher


class ProvisioningCipher(object):

    async def decrypt(self, provisionEnvelope):
        masterEphemeral = provisionEnvelope.publicKey
        message = provisionEnvelope.body
        if message[0] != 1:
            raise ValueError("Bad version number on ProvisioningMessage")
        iv = message[1:16 + 1]
        mac = message[-32:]
        ivAndCiphertext = message[:-32]
        ciphertext = message[16 + 1:-32]
        ecRes = Curve.calculateAgreement(masterEphemeral, self.keypair.privateKey)
        keys = HKDF.createFor(3).deriveSecrets(ecRes, "TextSecure Provisioning Message", 64)
        wm = WhisperMessage()
        wm.verifyMAC(1, ivAndCiphertext, keys[1], mac)
        plaintext = AESCipher(keys[0], iv).decrypt(ciphertext)
        provisionMessage = protobufs.ProvisionMessage.decode(plaintext)
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

    def get_publickey(self):
        if not self.keypair:
            self.keypair = Curve.generateKeyPair()
        return self.keypair.publicKey
