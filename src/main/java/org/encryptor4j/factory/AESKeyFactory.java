package org.encryptor4j.factory;

/**
 * <p>Factory class for creating secure keys.</p>
 * @author Martin
 *
 */
public class AESKeyFactory extends AbsKeyFactory {
	
	public static final String ALGORITHM = "AES";
	public static final int MAXIMUM_KEY_LENGTH = 256;

	public AESKeyFactory() {
		super(ALGORITHM, MAXIMUM_KEY_LENGTH);
	}
}