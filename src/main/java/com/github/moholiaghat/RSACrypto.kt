package com.github.moholiaghat

import java.util.*
import javax.crypto.Cipher

class RSACrypto(config: KeypperConfig) : RSABase(config) {
    fun encryptXMLFormat(xml: String, data: String): ByteArray {
        val publicKey = getPublicKeyFromXML(xml)

        val cipher = Cipher.getInstance("RSA", "BC")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)

        return cipher.doFinal(data.toByteArray())
    }

    fun encryptXMLFormatBase64(xml: String, data: String): String =
            Base64.getEncoder().encodeToString(encryptXMLFormat(xml, data))

    fun decrypt(xml: String, encryptedData: String): String {
        val privKey = getPrivateKeyFromXML(xml)

        val cipher = Cipher.getInstance("RSA", "BC")
        cipher.init(Cipher.DECRYPT_MODE, privKey)

        val decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedData))

        println("decrypted: " + String(decrypted))
        return String(decrypted)
    }

}