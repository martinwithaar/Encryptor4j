package org.encryptor4j.factory;

import java.security.Key;

import org.encryptor4j.Encryptor;

/**
 * <p>Factory interface for constructing <code>Encryptor</code> instances.</p>
 * @author Martin
 *
 */
public interface EncryptorFactory {
	/**
	 * AES <code>EncryptorFactory</code> implementation
	 */
	public static final EncryptorFactory AES = new AESEncryptorFactory();
	/**
	 * DES <code>EncryptorFactory</code> implementation
	 */
	public static final EncryptorFactory DES = new DESEncryptorFactory();
	/**
	 * <p>Returns an <code>Encryptor</code> instance usable for message encryption.</p>
	 * @param key
	 * @return
	 */
	Encryptor messageEncryptor(Key key);
	
	/**
	 * <p>Returns an <code>Encryptor</code> instance usable for streaming encryption.</p>
	 * @param key
	 * @return
	 */
	Encryptor streamEncryptor(Key key);
}
