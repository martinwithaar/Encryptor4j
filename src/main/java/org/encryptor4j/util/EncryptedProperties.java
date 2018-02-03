package org.encryptor4j.util;

import java.security.GeneralSecurityException;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Set;

/**
 *
 * @author Martin
 *
 */
public class EncryptedProperties extends Properties {

	/**
	 *
	 */
	private static final long serialVersionUID = 308603926591962322L;

	/*
	 * Attributes
	 */

	private TextEncryptor textEncryptor;

	/*
	 * Constructor(s)
	 */

	/**
	 *
	 * @param textEncryptor
	 */
	public EncryptedProperties(TextEncryptor textEncryptor) {
		super();
		this.textEncryptor = textEncryptor;
	}

	/*
	 * Overrides
	 */

	@Override
	public synchronized Object setProperty(String key, String value) {
		return super.setProperty(key, value);
	}

	@Override
	public String getProperty(String key) {
		try {
			return textEncryptor.decrypt(super.getProperty(textEncryptor.encrypt(key)));
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String getProperty(String key, String defaultValue) {
		try {
			String value = super.getProperty(textEncryptor.encrypt(key), defaultValue);
			if(value != null) {
				value = textEncryptor.decrypt(value);
			}
			return value;
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public Enumeration<?> propertyNames() {
		return super.propertyNames();
	}

	@Override
	public Set<String> stringPropertyNames() {
		return super.stringPropertyNames();
	}



}
