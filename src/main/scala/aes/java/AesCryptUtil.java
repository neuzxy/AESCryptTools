package aes.java;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AesCryptUtil {

    // Random IV length
    private static final int IV_LENGTH = 16;

    private static byte[] readKey(String keyPath) {
        byte[] key = null;

        try {
            key = Files.readAllBytes(Paths.get(keyPath));
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
        return key;
    }

    // Base64.encode(IV + cipherText)
    public static String encrypt(String plainText, byte[] key) {
        String encryptIVAndText = null;

        byte[] plainTextBytes = plainText.getBytes();

        // Generate random IV
        IvParameterSpec ivParameterSpec = createIv();
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        byte[] encrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            encrypted = cipher.doFinal(plainTextBytes);

            // Combine IV and encrypt part
            byte[] encryptedIVAndTextBytes = new byte[IV_LENGTH + encrypted.length];
            byte[] iv = ivParameterSpec.getIV();
            System.arraycopy(iv, 0, encryptedIVAndTextBytes, 0, IV_LENGTH);
            System.arraycopy(encrypted, 0, encryptedIVAndTextBytes, IV_LENGTH, encrypted.length);
            encryptIVAndText = Base64.getEncoder().encodeToString(encryptedIVAndTextBytes);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.println(e.getMessage());
        } finally {
            plainTextBytes = null; //delete plainText
        }

        return encryptIVAndText;
    }

    public static String decrypt(String encryptIVAndText, byte[] key) {
        String plainText = null;

        // Extract IV
        byte[] encryptedIVAndTextBytes = Base64.getDecoder().decode(encryptIVAndText);
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(encryptedIVAndTextBytes, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Extract encrypt part
        int encrytedSize = encryptedIVAndTextBytes.length - IV_LENGTH;
        byte[] ciperTextBytes = new byte[encrytedSize];

        System.arraycopy(encryptedIVAndTextBytes, IV_LENGTH, ciperTextBytes, 0, encrytedSize);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        byte[] plainTextBytes = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            plainTextBytes = cipher.doFinal(ciperTextBytes);
            plainText = new String(plainTextBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.println(e.getMessage());
        } finally {
            plainTextBytes = null;
        }

        return plainText;
    }

    private static IvParameterSpec createIv() {
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static void main(String[] args) {
        byte[] key = readKey("key.bin");
        String testText = "hello, world";
        String cipherText = AesCryptUtil.encrypt(testText, key);
        String plainText = AesCryptUtil.decrypt(cipherText, key);

        assert (plainText.equals(testText));
    }

}
