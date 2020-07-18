package com.github.moholiaghat

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import org.bouncycastle.util.io.pem.PemWriter
import java.io.StringReader
import java.io.StringWriter
import java.math.BigInteger
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64.getDecoder
import java.util.regex.Pattern

open class RSABase(protected val config: KeypperConfig) {
    private val rsaFactory: KeyFactory
    private val rsaKeyPairGenerator: KeyPairGenerator
    private val RSA_KEY_LEN = config.RSA_KEY_LEN

    init {
        Security.addProvider(BouncyCastleProvider())
        rsaFactory = KeyFactory.getInstance("RSA", "BC")
        rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC")
        rsaKeyPairGenerator.initialize(RSA_KEY_LEN)
    }

    fun generateKeyPair(): KeyPair = rsaKeyPairGenerator.generateKeyPair()

    fun getPrivateKeyFromPem(key: String): PrivateKey {
        val content = getPemObjectContent(key)
        val encodedKeySpec = PKCS8EncodedKeySpec(content)
        return rsaFactory.generatePrivate(encodedKeySpec)
    }

    fun getPublicKeyFromPem(key: String): PublicKey {
        val content = getPemObjectContent(key)
        val publicKeySpec = X509EncodedKeySpec(content)
        return rsaFactory.generatePublic(publicKeySpec)
    }

    private fun getPemObjectContent(key: String): ByteArray =
            PemReader(StringReader(key)).use { pemReader -> pemReader.readPemObject().content }

    fun getPublicKeyFromXML(xml: String): PublicKey {
        data class Test(val modulus: BigInteger, val exponent: BigInteger)

        val pattern =
                "<Modulus>(?<mod>\\*)</Modulus>\n<Exponent>(?<exp>\\*)</Exponent>"
        val matchVersion = Pattern.compile(pattern).matcher(xml)

        val test = if (matchVersion.find()) {
            val modulus = matchVersion.group("mod")?.let {
                BigInteger(1, getDecoder().decode(it))
            } ?: error("Version does not have major.")

            val exponent = matchVersion.group("exp")?.let {
                BigInteger(1, getDecoder().decode(it))
            } ?: error("Version does not have minor.")

            Test(modulus, exponent)
        } else
            error("can not fined pattern")

        val publicKeySpec = with(test) { RSAPublicKeySpec(modulus, exponent) }

        return rsaFactory.generatePublic(publicKeySpec)
    }

    fun getPrivateKeyFromXML(xml: String): PrivateKey {
        data class Test(val modulus: BigInteger, val d: BigInteger)

        val pattern =
                "<Modulus>(?<mod>\\*)</Modulus>\n<Exponent>(?<exp>\\*)</Exponent>\\*<D>(?<d>\\*)</D>"
        val matchVersion = Pattern.compile(pattern).matcher(xml)

        val test = if (matchVersion.find()) {
            val modulus = matchVersion.group("mod")?.let {
                BigInteger(1, getDecoder().decode(it))
            } ?: error("Version does not have major.")

            val d = matchVersion.group("d")?.let {
                BigInteger(1, getDecoder().decode(it))
            } ?: error("Version does not have major.")

            Test(modulus, d)
        } else
            error("can not fined pattern")

        val privateKeySpec = with(test) { RSAPrivateKeySpec(modulus, d) }

        return rsaFactory.generatePrivate(privateKeySpec)
    }

    fun getPubKeyFromXml(modules: String, exponent: String): PublicKey {
        val modulus = BigInteger(1, getDecoder().decode(modules))
        val expo = BigInteger(1, getDecoder().decode(exponent))

        val publicKeySpec = RSAPublicKeySpec(modulus, expo)
        return rsaFactory.generatePublic(publicKeySpec)
    }

    fun getPriKeyFromXml(modules: String, dElement: String): PrivateKey {
        val modulus = BigInteger(1, getDecoder().decode(modules))
        val delem = BigInteger(1, getDecoder().decode(dElement))

        val privateKeySpec = RSAPrivateKeySpec(modulus, delem)
        return rsaFactory.generatePrivate(privateKeySpec)
    }

    fun pubKeyToString(key: PublicKey): String {
        val pemObject = PemObject("PUBLIC KEY", key.encoded)
        StringWriter().use { out ->
            PemWriter(out).use { pemWriter ->
                pemWriter.writeObject(pemObject)
                pemWriter.flush()
                return out.toString()
            }
        }
    }

    fun privKeyToString(key: PrivateKey): String {
        val pemObject = PemObject("RSA PRIVATE KEY", key.encoded)
        StringWriter().use { out ->
            PemWriter(out).use { pemWriter ->
                pemWriter.writeObject(pemObject)
                pemWriter.flush()
                return out.toString()
            }
        }
    }
}
