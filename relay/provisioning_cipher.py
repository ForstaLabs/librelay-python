"""
Device onboarding protocol
"""

from . import protobufs
from axolotl.ecc.curve import Curve


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
        ecRes = curve.calculateAgreement(masterEphemeral, self.keypair.privKey)
        keys = crypto.HKDF(ecRes, Buffer.alloc(32), "TextSecure Provisioning Message")
        await libsignal.crypto.verifyMAC(ivAndCiphertext, keys[1], mac, 32)
        plaintext = await libsignal.crypto.decrypt(keys[0], ciphertext, iv)
        provisionMessage = protobufs.ProvisionMessage.decode(plaintext)
        privKey = provisionMessage.identityKeyPrivate
        return {
            identityKeyPair: libsignal.crypto.createKeyPair(privKey),
            addr: provisionMessage.addr,
            provisioningCode: provisionMessage.provisioningCode,
            userAgent: provisionMessage.userAgent
        }

    async def encrypt(self, theirPublicKey, message):
        assert(theirPublicKey instanceof Buffer)
        ourKeyPair = libsignal.crypto.generateKeyPair()
        sharedSecret = libsignal.crypto.calculateAgreement(theirPublicKey,
                                                                 ourKeyPair.privKey)
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
        pEnvelope.publicKey = ourKeyPair.pubKey
        return pEnvelope

    def get_publickey() {
        if not self.keypair:
            self.keypair = crypto.generateKeyPair()
        return self.keypair.pubKey
