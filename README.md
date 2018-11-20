[![Maven Central](https://img.shields.io/badge/Maven%20Central-0.1.2-blue.svg)](https://mvnrepository.com/artifact/org.encryptor4j/encryptor4j/0.1.2)
[![Android Arsenal](https://img.shields.io/badge/Android_Arsenal-Encryptor4j-brightgreen.svg)](https://android-arsenal.com/details/1/5573)

# Encryptor4j
Strong encryption for Java simplified

## Get it
Add this line to your *build.gradle*'s dependencies:

```
compile 'org.encryptor4j:encryptor4j:0.1.2'
```

## Overview
Encryptor4j consists of a set of wrapper and utility classes that make leveraging cryptography in your application alot easier.
It enables developers to encrypt and decrypt with little room for error, using few lines of code and supports all popular encryption algorithms such as AES, DES, RSA etc.

## Encryption
*Encryptor* is a small wrapper class for Java that greatly reduces boilerplate when implementing cryptography in an application.
It handles initialization vectors (IVs) transparently by securely generating and prepending them to the encrypted message. The IV is then read and used for decryption at a later time.

The Encryptor class is thread-safe and can thus be used by multiple threads.

### Message encryption
Encrypting a message using AES in CBC mode is as simple as this:

```java
String message = "This string has been encrypted & decrypted using AES in Cipher Block Chaining mode";
SecretKey secretKey = KeyFactory.AES.randomKey();
Encryptor encryptor = new Encryptor(secretKey, "AES/CBC/PKCS5Padding", 16);
byte[] encrypted = encryptor.encrypt(message.getBytes());
```

Using AES in GCM mode needs an additional *tLen* value in the constructor:

```java
String message = "This string has been encrypted & decrypted using AES in Galois Counter Mode";
SecretKey secretKey = KeyFactory.AES.randomKey();
Encryptor encryptor = new Encryptor(secretKey, "AES/GCM/NoPadding", 16, 128);
byte[] encrypted = encryptor.encrypt(message.getBytes());
```

Decrypting a message is done like this:

```java
// Assuming the same secret key is used
Encryptor encryptor = new Encryptor(secretKey, "AES/GCM/NoPadding", 16, 128);
byte[] decrypted = encryptor.decrypt(encrypted);
System.out.println(new String(decrypted));
```

### Streaming encryption

Streaming encryption can be done with relative ease: Just wrap any existing *InputStream* or *OutputStream* using an *Encryptor* instance.
The *Encryptor* will prepend the IV transparently and use the cipher that it has been constructed with.

The following example reads a file and writes it to another file using streaming encryption:

```java
SecretKey secretKey = KeyFactory.AES.randomKey();
Encryptor encryptor = new Encryptor(secretKey, "AES/CTR/NoPadding", 16);

InputStream is = null;
OutputStream os = null;
try {
  is = new FileInputStream("original.jpg");
  os = encryptor.wrapOutputStream(new FileOutputStream("encrypted.jpg"));
  byte[] buffer = new byte[4096];
  int nRead;
  while((nRead = is.read(buffer)) != -1) {
    os.write(buffer, 0, nRead);
  }
  os.flush();
} finally {
  if(is != null) {
    is.close();
  }
  if(os != null) {
    os.close();
  }
}
```

Decryption:

```java
// Assuming the same secret key is used
Encryptor encryptor = new Encryptor(secretKey, "AES/CTR/NoPadding", 16);

InputStream is = null;
OutputStream os = null;

try {
  is = encryptor.wrapInputStream(new FileInputStream("encrypted.jpg"));
  os = new FileOutputStream("decrypted.jpg");
  byte[] buffer = new byte[4096];
  int nRead;
  while((nRead = is.read(buffer)) != -1) {
    os.write(buffer, 0, nRead);
  }
  os.flush();
} finally {
  if(is != null) {
    is.close();
  }
  if(os != null) {
    os.close();
  }
}
```

## Encryption utilities
Encryptor4j comes with utility classes for performing common encryption tasks.

### File encryption
The *FileEncryptor* class encrypts and decrypts files and can be invoked from the command line.

Encryption:

```java
File srcFile = new File("original.zip");
File destFile = new File("original.zip.encrypted");
String password = "mysupersecretpassword";
FileEncryptor fe = new FileEncryptor(password);
fe.encrypt(srcFile, destFile);
```

Decryption:

```java
File srcFile = new File("original.zip.encrypted");
File destFile = new File("decrypted.zip");
String password = "mysupersecretpassword";
FileEncryptor fe = new FileEncryptor(password);
fe.decrypt(srcFile, destFile);
```

By default *FileEncryptor* uses AES in CTR mode with the maximum key length permitted (up to 256-bit).

### Text encryption
The *TextEncryptor* class encrypts and decrypts text using Base64 encoding for the encrypted message and can be invoked from the command line.

Encryption:

```java
String text = "This is a secret message";
String password = "mysupersecretpassword";
TextEncryptor te = new TextEncryptor(password);
String encrypted = te.encrypt(text);
```

Decryption:

```java
String encrypted = "5Zz0WGJ5XK1YDxs7O5VX7nhBaNeFWnvz/RBxmfawammmkNZhWeTJkMIQ/RWIPDmx";
String password = "mysupersecretpassword";
TextEncryptor te = new TextEncryptor(password);
String text = te.decrypt(encrypted);
```

By default *TextEncryptor* uses AES in CBC mode with the maximum key length permitted (up to 256-bit).

## Key agreement
Key agreement protocols such as Diffie-Hellman and Elliptic Curve Diffie-Hellman have gained significant popularity in the past years.
Encryptor4j comes with wrapper classes that further simplify these processes.

A simple DH key agreement can be written like this:

```java
// Create primes p & g
// Tip: You don't need to regenerate p; Use a fixed value in your application
int bits = 2048;
BigInteger p = BigInteger.probablePrime(bits, new SecureRandom());
BigInteger g = new BigInteger("2");

// Create two peers
KeyAgreementPeer peerA = new DHPeer(p, g);
KeyAgreementPeer peerB = new DHPeer(p, g);

// Exchange public keys and compute shared secret
byte[] sharedSecretA = peerA.computeSharedSecret(peerB.getPublicKey());
byte[] sharedSecretB = peerB.computeSharedSecret(peerA.getPublicKey());
```

an ECDH key agreement like this:

```java
String algorithm = "brainpoolp256r1";

// Create two peers
KeyAgreementPeer peerA = new ECDHPeer(algorithm);
KeyAgreementPeer peerB = new ECDHPeer(algorithm);

// Exchange public keys and compute shared secret
byte[] sharedSecretA = peerA.computeSharedSecret(peerB.getPublicKey());
byte[] sharedSecretB = peerB.computeSharedSecret(peerA.getPublicKey());
```

Key agreement protocols like this can be used to set up encrypted messaging or streaming as shown above.
Setup an *Encryptor* instance with the freshly obtained shared secret:

```java
byte[] sharedSecret = peer.computeSharedSecret(publicKey);
SecretKey secretKey = new SecretKeySpec(sharedSecret, "AES");
Encryptor encryptor = new Encryptor(secretKey, "AES/CTR/NoPadding", 16);
```

## Custom IV handling
When using block modes that need an IV the *Encryptor* instance handles the generation and prepending automatically.
This behavior can be overridden by using an explicit IV or by not prepending the IV when a custom means of transmission is required.

Encrypt data using an explicit IV:

```java
Encryptor encryptor = new Encryptor(secretKey, "AES/CBC/PKCS5Padding", 16);
byte[] iv = new byte[] { 107, 67, 98, -81, 54, -31, -110, -63, 24, 76, -12, -48, -55, 14, 15, 19 };
byte[] encrypted = encryptor.encrypt(data, null, iv);
```

Disable prepending of the IV by calling:

```java
encryptor.setPrependIV(false);
```

You will have to store the IV yourself in order to properly decrypt a ciphertext.

## Disable IV generation
Sometimes the *Cipher* implementation used by the VM does not permit passing the IV via the algorithm parameters because it will generate it itself (such as with some versions of Android). The automatic IV generation functionality of the *Encryptor* class should then be disabled like so:

```java
encryptor.setGenerateIV(false);
```

## AEAD and Additional Authentication Data (AAD)
When using an AEAD (authenticated encryption with associated data) blockmode such as GCM it is possible to include additional associated data when encrypting or decrypting:

```java
byte[] aad = new byte[] { 74, 17, -123, -27, 21, 46, 57, 18, 111, -102, 98, -84, 8, -68, -23, 72 };
byte[] encrypted = encryptor.encrypt(message.getBytes(), aad);
```

This can be used to enhance the authentication strength of a cryptographic protocol if properly designed.

## Best practices
Encryption does not guarantee security out-of-the-box. A certain degree of understanding is required to choose the correct algorithm, block cipher mode, key size etc.

**Here are some tips:**
* Do not use DES: use AES instead; see https://en.wikipedia.org/wiki/Data_Encryption_Standard#Security_and_cryptanalysis
* Avoid ECB block cipher mode; see https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
* Prepare for quantum computers: Use large key sizes; see https://en.wikipedia.org/wiki/Key_size
* Use securely generated IVs such as those generated by a *SecureRandom* instance

## Javadoc
Consult the project's Javadoc at http://martinwithaar.github.io/Encryptor4j/

## Unlimited Strength Jurisdiction Policy
In order to use 256-bit keys with AES encryption you must download and install custom policy files made available by Oracle:

* Visit http://www.oracle.com/technetwork/java/javase/downloads/index.html
* Scroll down and download the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files
* Installation instructions are included in the downloadable zip file
