package org.encryptor4j.test;
import org.encryptor4j.Encryptor;
import org.junit.Test;

import static org.junit.Assert.*;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

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
	
	private static final int AES_KEY_SIZE = 256;
	private static final int DES_KEY_SIZE = 64;
	
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	// AES
	
    @Test public void testAES_ECB() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using AES in Electronic Codebook mode";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("AES", AES_KEY_SIZE), "AES/ECB/PKCS5Padding");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    @Test public void testAES_CBC() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using AES in Cipher Block Chaining mode";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("AES", AES_KEY_SIZE), "AES/CBC/PKCS5Padding", 16);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    @Test public void testAES_CTR() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using AES in Counter mode";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("AES", AES_KEY_SIZE), "AES/CTR/NoPadding", 16);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    @Test public void testAES_CFB() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using AES in Cipher Feedback mode";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("AES", AES_KEY_SIZE), "AES/CFB/NoPadding", 16);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    @Test public void testAES_OFB() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using AES in Output Feedback mode";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("AES", AES_KEY_SIZE), "AES/OFB/NoPadding", 16);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    @Test public void testAES_GCM() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using AES in Galois Counter Mode";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("AES", AES_KEY_SIZE), "AES/GCM/NoPadding", 16, 128);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    // DES
    
    @Test public void testDES_ECB() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using DES in Electronic Codebook mode";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("DES", DES_KEY_SIZE), "DES/ECB/PKCS5Padding");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    @Test public void testDES_CBC() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using DES in Cipher Block Chaining mode";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("DES", DES_KEY_SIZE), "DES/CBC/PKCS5Padding", 8);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    @Test public void testDES_CTR() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using DES in Counter mode";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("DES", DES_KEY_SIZE), "DES/CTR/NoPadding", 8);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    @Test public void testDES_CFB() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using DES in Cipher Feedback mode";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("DES", DES_KEY_SIZE), "DES/CFB/NoPadding", 8);
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    @Test public void testDES_OFB() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using DES in Output Feedback mode";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("DES", DES_KEY_SIZE), "DES/OFB/NoPadding", 8);
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
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("Blowfish", AES_KEY_SIZE), "Blowfish");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    @Test public void testTwofish() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using Twofish";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("Twofish", AES_KEY_SIZE), "Twofish");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    // ARC4
    
    @Test public void testARC4() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using ARC4";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("ARC4", AES_KEY_SIZE), "ARC4");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    // RC2
    
    @Test public void testRC2() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using RC2";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("RC2", AES_KEY_SIZE), "RC2");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    // RC4
    
    @Test public void testRC4() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using RC4";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("RC4", AES_KEY_SIZE), "RC4");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
    
    // RC5
    
    @Test public void testRC5() throws GeneralSecurityException {
    	String message = "This string has been encrypted & decrypted using RC5";
		Encryptor encryptor = new Encryptor(Encryptor.generateSecretKey("RC5", AES_KEY_SIZE), "RC5");
		encryptor.setAlgorithmProvider("BC");
		byte[] encrypted = encryptor.encrypt(message.getBytes());
		byte[] decrypted = encryptor.decrypt(encrypted);
		assertEquals(message, new String(decrypted));
    }
}
