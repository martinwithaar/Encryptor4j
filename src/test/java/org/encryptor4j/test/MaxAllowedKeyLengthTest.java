package org.encryptor4j.test;

import static org.junit.Assert.assertEquals;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;

import org.junit.Test;

/**
 * <p>Tests whether the Java Cryptography Extension (JCE) unlimited strength jurisdiction policy files have been installed.</p>
 * @author Martin
 *
 */
public class MaxAllowedKeyLengthTest {

	@Test public void maxAllowedKeyLengthTest() throws GeneralSecurityException {
		String[] algorithms = new String[] { "AES", "DES", "RSA", "Blowfish", "RC2", "RC4", "RC5", "ARC4"};
		for(String algorithm: algorithms) {
			int maxKeyLength = Cipher.getMaxAllowedKeyLength(algorithm);
			System.out.println(algorithm + ": " + maxKeyLength);
			assertEquals(Integer.MAX_VALUE, maxKeyLength);
		}
	}
}
