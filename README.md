# AES/CBC Crypt Tools in Java and Scala

## Generate Random Key

```
head -c16 /dev/urandom > key.bin
```

## API
* `readKey(String keyPath)`: return key in byte array
* `encrypt(String plainText, byte[] key)`: return base64 encoded cipherText with random IV
* `decrypt(String encryptIVAndText, byte[] key)`: return decrypted plainText
