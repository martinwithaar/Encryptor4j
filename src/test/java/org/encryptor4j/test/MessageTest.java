package org.encryptor4j.test;
import org.encryptor4j.Encryptor;
import org.encryptor4j.factory.KeyFactory;
import org.junit.Test;

import static org.junit.Assert.*;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.KeyGenerator;

/**
 * <p>Unit test that tests message encryption using the <code>Encryptor</code> class.</p>
 * <p>Tests the following algorithms using multiple block modes when possible:</p>
 * <ul>
 * <li>AES</li>
 * <li>DES</li>
 * <li>RSA</li>
 * <li>Blowfish</li>
 * <li>ARC4</li>
 * <li>RC2</li>
 * <li>RC4</li>
 * <li>RC5</li>
 * </ul>
 * @see <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher">http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher</a>
 * @author Martin
 *
 */
public class MessageTest {

	private static final int KEY_SIZE = 256;

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	// AES

    @Test public void testAES_ECB() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using AES in Electronic Codebook mode";
		Encryptor encryptor = new Encryptor(KeyFactory.AES.randomKey(), "AES/ECB/PKCS5Padding");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    @Test public void testAES_CBC() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using AES in Cipher Block Chaining mode";
		Encryptor encryptor = new Encryptor(KeyFactory.AES.randomKey(), "AES/CBC/PKCS5Padding", 16);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    @Test public void testAES_CTR() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using AES in Counter mode";
		Encryptor encryptor = new Encryptor(KeyFactory.AES.randomKey(), "AES/CTR/NoPadding", 16);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    @Test public void testAES_CFB() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using AES in Cipher Feedback mode";
		Encryptor encryptor = new Encryptor(KeyFactory.AES.randomKey(), "AES/CFB/NoPadding", 16);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    @Test public void testAES_OFB() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using AES in Output Feedback mode";
		Encryptor encryptor = new Encryptor(KeyFactory.AES.randomKey(), "AES/OFB/NoPadding", 16);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    @Test public void testAES_GCM() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using AES in Galois Counter Mode";
		Encryptor encryptor = new Encryptor(KeyFactory.AES.randomKey(), "AES/GCM/NoPadding", 16, 128);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    // DES

    @Test public void testDES_ECB() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using DES in Electronic Codebook mode";
		Encryptor encryptor = new Encryptor(KeyFactory.DES.randomKey(), "DES/ECB/PKCS5Padding");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    @Test public void testDES_CBC() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using DES in Cipher Block Chaining mode";
		Encryptor encryptor = new Encryptor(KeyFactory.DES.randomKey(), "DES/CBC/PKCS5Padding", 8);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    @Test public void testDES_CTR() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using DES in Counter mode";
		Encryptor encryptor = new Encryptor(KeyFactory.DES.randomKey(), "DES/CTR/NoPadding", 8);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    @Test public void testDES_CFB() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using DES in Cipher Feedback mode";
		Encryptor encryptor = new Encryptor(KeyFactory.DES.randomKey(), "DES/CFB/NoPadding", 8);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    @Test public void testDES_OFB() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using DES in Output Feedback mode";
		Encryptor encryptor = new Encryptor(KeyFactory.DES.randomKey(), "DES/OFB/NoPadding", 8);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    // RSA

    @Test public void testRSA() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using RSA";
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

		Encryptor encryptor = new Encryptor(keyPair.getPublic(), "RSA");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());

		Encryptor decryptor = new Encryptor(keyPair.getPrivate(), "RSA");
		decryptor.setAlgorithmProvider("BC");
		byte[] decrypted = decryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    // Blowfish

    @Test public void testBlowfish() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using Blowfish";
		Encryptor encryptor = new Encryptor(randomKey("Blowfish", KEY_SIZE), "Blowfish");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    @Test public void testTwofish() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using Twofish";
		Encryptor encryptor = new Encryptor(randomKey("Twofish", KEY_SIZE), "Twofish");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    // ARC4

    @Test public void testARC4() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using ARC4";
		Encryptor encryptor = new Encryptor(randomKey("ARC4", KEY_SIZE), "ARC4");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    // RC2

    @Test public void testRC2() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using RC2";
		Encryptor encryptor = new Encryptor(randomKey("RC2", KEY_SIZE), "RC2");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    // RC4

    @Test public void testRC4() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using RC4";
		Encryptor encryptor = new Encryptor(randomKey("RC4", KEY_SIZE), "RC4");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    // RC5

    @Test public void testRC5() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using RC5";
		Encryptor encryptor = new Encryptor(randomKey("RC5", KEY_SIZE), "RC5");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }

    /*
     * Static methods
     */

    /**
     *
     * @param algorithm
     * @param size
     * @return
     */
	public static final Key randomKey(String algorithm, int size) {
    	try {
    		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
    		keyGenerator.init(size);
    		return keyGenerator.generateKey();
    	} catch(NoSuchAlgorithmException e) {
    		throw new RuntimeException(e);
    	}
    }
}
