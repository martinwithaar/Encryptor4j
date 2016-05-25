# Encryptor4j
Simplified strong encryption for Java

## Overview
Encryptor4j consists of a set of wrapper and utility classes that make leveraging cryptography in your application alot easier.
It enables developers to encrypt and decrypt with little room for error and using few lines of code.

It supports all popular encryption algorithms such as AES, DES, RSA etc.

## Encryption
*Encryptor* is a small wrapper class for Java that greatly reduces boilerplate when implementing cryptography in an application.
It handles initialization vectors (IVs) transparently by securely generating and prepending them to the encrypted message. This IV is then read and used for decryption at a later time.

### Message encryption
Encrypting a message using AES in CBC mode is as simple as this:
```java
String message = "This string has been encrypted & decrypted using AES in Cipher Block Chaining mode";
SecretKey secretKey = Encryptor.generateSecretKey("AES", 256);
Encryptor encryptor = new Encryptor(secretKey, "AES/CBC/PKCS5Padding", 16);
byte[] encrypted = encryptor.encrypt(message.getBytes());
```

Using AES in GCM mode needs an additional *tLen* value in the constructor:
```java
String message = "This string has been encrypted & decrypted using AES in Galois Counter Mode";
SecretKey secretKey = Encryptor.generateSecretKey("AES", 256);
Encryptor encryptor = new Encryptor(secretKey, "AES/GCM/NoPadding", 16, 128);
byte[] encrypted = encryptor.encrypt(message.getBytes());
```

Decrypting a message is simply done like this:
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
SecretKey secretKey = Encryptor.generateSecretKey("AES", 256);
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

Decrypting is easy too:
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

## Key agreement
Key agreement protocols such as Diffie-Hellman and Elliptic Curve Diffie-Hellman have gained significant popularity in the past years.
Encryptor4j comes with wrapper classes that further simplify these processes.

A simple DH key agreement can be written like this:
```java
// Create primes p & g
int bitLength = 512;
SecureRandom random = new SecureRandom();
BigInteger p = BigInteger.probablePrime(bitLength, random);
BigInteger g = BigInteger.probablePrime(bitLength, random);

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

Key agreement protocols like this can be used to set up encrypted messaging or streaming encryption as shown above.
Setup an *Encryptor* instance with the freshly obtained shared secret:

```java
byte[] sharedSecret = peer.computeSharedSecret(publicKey);
SecretKey secretKey = new SecretKeySpec(sharedSecret, "AES");
Encryptor encryptor = new Encryptor(secretKey, "AES/CTR/NoPadding", 16);
```

## Custom IV handling
When using block modes that need an IV the *Encryptor* instance handles the generation and prepending transparently.
This behavior can be overridden by using an explicit IV or by not prepending the IV when a custom means of transmission is required.

Construct an *Encryptor* instance using an explicit IV:
```java
SecretKey secretKey = Encryptor.generateSecretKey("AES", 256);
byte[] iv = new byte[] { 107, 67, 98, -81, 54, -31, -110, -63, 24, 76, -12, -48, -55, 14, 15, 19 };
Encryptor encryptor = new Encryptor(secretKey, "AES/CBC/PKCS5Padding", iv);
```

Disable prepending of the IV by calling:
```java
encryptor.setPrependIV(false);
```
