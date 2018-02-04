package aes.scala

import java.io.IOException
import java.nio.file.{Files, Paths}
import java.security.{InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, SecureRandom}
import java.util.Base64
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import javax.crypto.{BadPaddingException, Cipher, IllegalBlockSizeException, NoSuchPaddingException}

object AesCryptUtil {

  val IV_LENGTH = 16

  def readKey(filePath: String): Array[Byte] = {
    var key = Array.empty[Byte]

    try {
      key = Files.readAllBytes(Paths.get(filePath))
    } catch {
      case e: IOException => println(e.getMessage)
    }
    key
  }

  def encrypt(plainText: String, key: Array[Byte]): String = {
    var encryptIVAndText: String = ""

    var plainTextBytes = plainText.getBytes

    // Generate random IV
    val ivParameterSpec = createIV()
    val secretKeySpec = new SecretKeySpec(key, "AES")
    try {
      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec)
      val encrypted = cipher.doFinal(plainTextBytes)
      // Combine IV and encrypt part
      val encryptedIVAndTextBytes = new Array[Byte](IV_LENGTH + encrypted.length)
      val iv = ivParameterSpec.getIV
      Array.copy(iv, 0, encryptedIVAndTextBytes, 0, IV_LENGTH)
      Array.copy(encrypted, 0, encryptedIVAndTextBytes, IV_LENGTH, encrypted.length)
      encryptIVAndText = Base64.getEncoder.encodeToString(encryptedIVAndTextBytes)
    } catch {
      case e@(_: NoSuchAlgorithmException | _: NoSuchPaddingException | _
        : InvalidKeyException | _: InvalidAlgorithmParameterException | _
                : IllegalBlockSizeException | _: BadPaddingException
        ) => println(e.getMessage)
    } finally {
      plainTextBytes = null //delete plainText

    }

    return encryptIVAndText
  }

  def decrypt(encryptIVAndText: String, key: Array[Byte]): String = {
    var plainText = ""

    // Extract Iv
    val encryptedIVAndTextBytes = Base64.getDecoder.decode(encryptIVAndText)
    val iv = new Array[Byte](IV_LENGTH)
    Array.copy(encryptedIVAndTextBytes, 0, iv, 0, iv.length)
    val ivParameterSpec = new IvParameterSpec(iv)

    // Extract encrypt part
    val encrytedSize = encryptedIVAndTextBytes.length - IV_LENGTH
    val encryptedBytes = new Array[Byte](encrytedSize)

    Array.copy(encryptedIVAndTextBytes, IV_LENGTH, encryptedBytes, 0, encrytedSize)

    val secretKeySpec = new SecretKeySpec(key, "AES")
    var plainTextBytes = Array.empty[Byte]
    try {
      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec)
      plainTextBytes = cipher.doFinal(encryptedBytes)
      plainText = new String(plainTextBytes)
    } catch {
      case e@(_: NoSuchAlgorithmException | _: NoSuchPaddingException | _
        : InvalidKeyException | _: InvalidAlgorithmParameterException | _
                : IllegalBlockSizeException | _: BadPaddingException
        ) => println(e.getMessage)
    } finally {
      plainTextBytes = null
    }

    return plainText
  }

  def createIV(): IvParameterSpec = {
    val iv = new Array[Byte](IV_LENGTH)
    val secureRandom = new SecureRandom()
    secureRandom.nextBytes(iv)
    new IvParameterSpec(iv)
  }

  def main(args: Array[String]): Unit = {
    val key = readKey("key.bin")
    val testText = "hello, world"
    val cipherText = encrypt(testText, key)
    val plainText = decrypt(cipherText, key)
    assert(plainText == testText)
  }

}