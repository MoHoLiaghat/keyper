package com.github.moholiaghat

import java.io.BufferedReader
import java.io.FileReader

fun main() {
    val a = "<RSAKeyValue>" +
            "<Modulus>zEKvk9L95tFVU1nOEeL4IDfocHqjGn6nAVtHYb3mhn6ESuYBhTUBqRLeGaz2sgu6jM3C7XGjKS08vy08U14dGBQCRq51AV9o4gNNoH1TZYAQhGIGGzqDHEzjiugvhh8APV4kyQ4/NgpfjS2a7SWamg/stzB1debToW6AgpdSyG8=</Modulus>" +
            "<Exponent>AQAB</Exponent>" +
            "</RSAKeyValue>"

    val mod =
            "zEKvk9L95tFVU1nOEeL4IDfocHqjGn6nAVtHYb3mhn6ESuYBhTUBqRLeGaz2sgu6jM3C7XGjKS08vy08U14dGBQCRq51AV9o4gNNoH1TZYAQhGIGGzqDHEzjiugvhh8APV4kyQ4/NgpfjS2a7SWamg/stzB1debToW6AgpdSyG8="
    val exp = "AQAB"

    val crypto = RSABase(KeypperConfig())
    val publicKey = crypto.getPubKeyFromXml(mod, exp)
    val pubKeyToString = crypto.pubKeyToString(publicKey)

    val reader = BufferedReader(FileReader("src/main/resources/public.pem"))
    val text = reader.use { it.readText() }

    println(pubKeyToString == text)
}
