package org.encryptor4j.factory;

/**
 * <p>Factory class for creating secure keys.</p>
 * @author Martin
 *
 */
public class DESKeyFactory extends AbsKeyFactory {
	
	public static final String ALGORITHM = "DES";
	public static final int MAXIMUM_KEY_LENGTH = 64;

	public DESKeyFactory() {
		super(ALGORITHM, MAXIMUM_KEY_LENGTH);
	}
}