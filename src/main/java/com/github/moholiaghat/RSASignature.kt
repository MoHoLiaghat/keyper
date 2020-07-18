package com.github.moholiaghat

import java.security.Signature

class RSASignature(config: KeypperConfig) : RSABase(config) {

    fun signData(data: ByteArray, privateKeyPemFormat: String): ByteArray? {
        val sig = Signature.getInstance(config.algorithm.name).apply {
            initSign(getPrivateKeyFromPem(privateKeyPemFormat))
            update(data)
        }

        return sig.sign()
    }

    fun verifyData(data: ByteArray, signData: ByteArray, publicKeyPemFormat: String): Boolean {
        val sig = Signature.getInstance(config.algorithm.name).apply {
            initVerify(getPublicKeyFromPem(publicKeyPemFormat))
            update(data)
        }

        return sig.verify(signData)
    }
}
