package org.encryptor4j.preferences;

import java.security.GeneralSecurityException;
import java.util.prefs.AbstractPreferences;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

import org.encryptor4j.util.TextEncryptor;

/**
 * <p><code>AbstractPreferences</code> wrapper class implementation that encrypts key-value pairs transparently.</p>
 * @author Martin
 *
 */
public class EncryptedPreferences extends AbstractPreferences {

	/*
	 * Attributes
	 */

	private Preferences preferences;
	private TextEncryptor textEncryptor;

	/*
	 * Constructor(s)
	 */

	/**
	 *
	 * @param preferences
	 * @param name
	 */
	protected EncryptedPreferences(Preferences preferences, String name) {
		this(preferences, preferences.name(), new TextEncryptor());
	}

	/**
	 *
	 * @param preferences
	 * @param name
	 * @param textEncryptor
	 */
	protected EncryptedPreferences(Preferences preferences, String name, TextEncryptor textEncryptor) {
		super(null, name);
		this.preferences = preferences;
	}

	/*
	 * Class methods
	 */

	/**
	 * <p>Returns the inner <code>Preferences</code>.</p>
	 * @return
	 */
	public Preferences getPreferences() {
		return preferences;
	}

	/**
	 * <p>Returns the <code>TextEncryptor</code>.</p>
	 * @return
	 */
	public TextEncryptor getTextEncryptor() {
		return textEncryptor;
	}

	/*
	 * Concrete methods
	 */

	@Override
	protected void putSpi(String key, String value) {
		try {
			preferences.put(textEncryptor.encrypt(key), textEncryptor.encrypt(value));
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected String getSpi(String key) {
		try {
			String value = preferences.get(textEncryptor.encrypt(key), null);
			if(value != null) {
				value = textEncryptor.decrypt(value);
			}
			return value;
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void removeSpi(String key) {
		try {
			preferences.remove(textEncryptor.encrypt(key));
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void removeNodeSpi() throws BackingStoreException {
		preferences.removeNode();
	}

	@Override
	protected String[] keysSpi() throws BackingStoreException {
		String[] keys = preferences.keys();
		for(int i = 0, n = keys.length; i < n; i++) {
			try {
				keys[i] = textEncryptor.decrypt(keys[i]);
			} catch (GeneralSecurityException e) {
				throw new RuntimeException(e);
			}
		}
		return keys;
	}

	@Override
	protected String[] childrenNamesSpi() throws BackingStoreException {
		return preferences.childrenNames();
	}

	@Override
	protected AbstractPreferences childSpi(String name) {
		return (AbstractPreferences) preferences.node(name);
	}

	@Override
	protected void syncSpi() throws BackingStoreException {
		preferences.sync();
	}

	@Override
	protected void flushSpi() throws BackingStoreException {
		preferences.flush();
	}

}
