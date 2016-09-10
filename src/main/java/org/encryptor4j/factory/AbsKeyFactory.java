package org.encryptor4j.factory;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>Abstract <code>KeyFactory</code> implementation for creating secure keys.</p>
 * @author Martin
 *
 */
public abstract class AbsKeyFactory implements KeyFactory {

	public static final byte[] DEFAULT_SALT = new byte[] { 73, 32, -12, -103, 88, 14, -44, 9, -119, -42, 5, -63, 102, -11, -104, 66, -17, 112, 55, 44, 18, -46, 30, -6, -55, 28, -54, 12, 39, 110, 63, 125 };
	public static final int DEFAULT_ITERATION_COUNT = 65536;
	
	/*
	 * Attributes
	 */
	
	private String algorithm;
	private byte[] salt;
	private int iterationCount;
	private int maximumKeyLength;
	
	/*
	 * Constructor(s)
	 */
	
	/**
	 * 
	 * @param algorithm
	 * @param maximumKeyLength
	 */
	public AbsKeyFactory(String algorithm, int maximumKeyLength) {
		this(algorithm, maximumKeyLength, DEFAULT_SALT, DEFAULT_ITERATION_COUNT);
	}
	
	/**
	 * 
	 * @param algorithm
	 * @param maximumKeyLength
	 * @param salt
	 * @param iterationCount
	 */
	public AbsKeyFactory(String algorithm, int maximumKeyLength, byte[] salt, int iterationCount) {
		this.algorithm = algorithm;
		this.maximumKeyLength = maximumKeyLength;
		this.salt = salt;
		this.iterationCount = iterationCount;
	}
	
	/*
	 * Class methods
	 */
	
	/**
	 * 
	 * @param salt
	 */
	public void setSalt(byte[] salt) {
		this.salt = salt;
	}
	
	/**
	 * 
	 * @param iterationCount
	 */
	public void setIterationCount(int iterationCount) {
		this.iterationCount = iterationCount;
	}
	
	/*
	 * Interface implementations
	 */
	
	@Override
	public final Key keyFromPassword(char[] password) {
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			int keyLength = Math.min(Cipher.getMaxAllowedKeyLength(algorithm), maximumKeyLength);
			KeySpec spec = new PBEKeySpec(password, salt, iterationCount, keyLength);
			SecretKey tmp = factory.generateSecret(spec);
			return new SecretKeySpec(tmp.getEncoded(), algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
    public final Key randomKey() {
    	try {
    		int keyLength = Math.min(Cipher.getMaxAllowedKeyLength(algorithm), maximumKeyLength);
    		return randomKey(keyLength);
    	} catch(NoSuchAlgorithmException e) {
    		throw new RuntimeException(e);
    	}
    }
    
	@Override
    public final Key randomKey(int size) {
    	try {
    		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
    		keyGenerator.init(size);
    		return keyGenerator.generateKey();
    	} catch(NoSuchAlgorithmException e) {
    		throw new RuntimeException(e);
    	}
    }
}
