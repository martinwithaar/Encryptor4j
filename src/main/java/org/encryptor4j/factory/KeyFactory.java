package org.encryptor4j.factory;

import java.security.Key;

/**
 * <p>Factory interface for generating keys.</p>
 * @author Martin
 *
 */
public interface KeyFactory {
	/**
	 * AES <code>KeyFactory</code> implementation
	 */
	public static final KeyFactory AES = new AESKeyFactory();
	/**
	 * AES <code>KeyFactory</code> implementation
	 */
	public static final KeyFactory DES = new DESKeyFactory();
	/**
	 * <p>Derives and returns a strong key from a password.</p>
	 * @param password
	 * @return
	 */
	Key keyFromPassword(char[] password);
	/**
	 * <p>Generates a strong random key.</p>
	 * @return
	 */
	Key randomKey();
	/**
	 * <p>Generates a random key of size <code>size</code>.</p>
	 * @param size
	 * @return
	 */
	Key randomKey(int size);
}
