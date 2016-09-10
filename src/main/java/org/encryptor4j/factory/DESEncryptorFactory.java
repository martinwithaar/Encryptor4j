package org.encryptor4j.factory;

import java.security.Key;

import org.encryptor4j.Encryptor;

/**
 * <p>Factory class for constructing DES <code>Encryptor</code> instances.</p>
 * @author Martin
 *
 */
public class DESEncryptorFactory implements EncryptorFactory {
	
	@Override
	public final Encryptor messageEncryptor(Key key) {
		return new Encryptor(key, "DES/CBC/PKCS5Padding", 16);
	}
	
	@Override
	public final Encryptor streamEncryptor(Key key) {
		return new Encryptor(key, "DES/CTR/NoPadding", 16);
	}
}
