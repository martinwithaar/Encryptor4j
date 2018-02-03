package org.encryptor4j;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * <p>Encryptor class that greatly simplifies strong encryption and decryption.</p>
 * <p>Supports both encryption/decryption of single messages as well as streaming encryption.
 * Handling of initialization vectors (IVs) is done transparently. You can alter this behavior
 * by calling {@link #setPrependIV(boolean)}.</p>
 *
 * @author Martin
 *
 */
public class Encryptor {

	private static final String DEFAULT_ALGORITHM = "AES";

    /*
     * Attributes
     */

	private String algorithm;
	private String algorithmProvider;
	private int ivLength;
	private int tLen;
	private Key key;
	private KeySpec keySpec;
	private SecretKeyFactory secretKeyFactory;
	private ThreadLocal<byte[]> ivThreadLocal;
	private ThreadLocal<Cipher> cipherThreadLocal;
	private boolean prependIV;
	private boolean generateIV;

    /*
     * Constructor(s)
     */

	/**
	 * <p>Constructs an <code>Encryptor</code> instance.</p>
	 * @param key
	 */
	public Encryptor(Key key) {
		this(key, DEFAULT_ALGORITHM);
	}

	/**
	 * <p>Constructs an <code>Encryptor</code> instance.</p>
	 * @param key
	 * @param algorithm
	 */
	public Encryptor(Key key, String algorithm) {
		this(key, algorithm, 0);
	}

	/**
	 * <p>Constructs an <code>Encryptor</code> instance.</p>
	 * @param key
	 * @param algorithm
	 * @param ivLength
	 */
	public Encryptor(Key key, String algorithm, int ivLength) {
		this(key, algorithm, ivLength, 0);
	}

	/**
	 * <p>Constructs an <code>Encryptor</code> instance.</p>
	 * <p>Use this constructor when using GCM block mode and specify the <code>tLen</code> value.</p>
	 * @param key
	 * @param algorithm
	 * @param ivLength
	 * @param tLen
	 */
	public Encryptor(Key key, String algorithm, int ivLength, int tLen) {
		this.key = key;
		this.algorithm = algorithm;
		this.ivLength = ivLength;
		this.tLen = tLen;
		this.ivThreadLocal = new ThreadLocal<>();
		this.cipherThreadLocal = new ThreadLocal<>();
		this.prependIV = this.generateIV = true;
	}

	/**
	 * <p>Constructs an <code>Encryptor</code> instance.</p>
	 * @param keySpec
	 * @param secretKeyFactory
	 */
	public Encryptor(KeySpec keySpec, SecretKeyFactory secretKeyFactory) {
		this(keySpec, secretKeyFactory, DEFAULT_ALGORITHM, 0);
	}

	/**
	 * <p>Constructs an <code>Encryptor</code> instance.</p>
	 * @param keySpec
	 * @param secretKeyFactory
	 * @param algorithm
	 * @param ivLength
	 */
	public Encryptor(KeySpec keySpec, SecretKeyFactory secretKeyFactory, String algorithm, int ivLength) {
		this(keySpec, secretKeyFactory, DEFAULT_ALGORITHM, ivLength, 0);
	}

	/**
	 * <p>Constructs an <code>Encryptor</code> instance.</p>
	 * <p>Use this constructor when using GCM block mode and specify the <code>tLen</code> value.</p>
	 * @param keySpec
	 * @param secretKeyFactory
	 * @param algorithm
	 * @param ivLength
	 * @param tLen
	 */
	public Encryptor(KeySpec keySpec, SecretKeyFactory secretKeyFactory, String algorithm, int ivLength, int tLen) {
		this.keySpec = keySpec;
		this.secretKeyFactory = secretKeyFactory;
		this.algorithm = algorithm;
		this.ivLength = ivLength;
		this.tLen = tLen;
		this.ivThreadLocal = new ThreadLocal<>();
		this.cipherThreadLocal = new ThreadLocal<>();
		this.prependIV = this.generateIV = true;
	}

    /*
     * Class methods
     */

	/**
	 * <p>Encrypts a byte array and returns the encrypted message.</p>
	 * @param message
	 * @return
	 * @throws GeneralSecurityException
	 */
	public byte[] encrypt(byte[] message) throws GeneralSecurityException {
		return encrypt(message, null);
	}

	/**
	 * <p>Encrypts a byte array and returns the encrypted message.</p>
	 * @param message
	 * @param aad
	 * @return
	 * @throws GeneralSecurityException
	 */
	public byte[] encrypt(byte[] message, byte[] aad) throws GeneralSecurityException {
		return encrypt(message, aad, null);
	}

	/**
	 * <p>Encrypts a byte array and returns the encrypted message.</p>
	 * @param message
	 * @param aad
	 * @param iv
	 * @return
	 * @throws GeneralSecurityException
	 */
	public byte[] encrypt(byte[] message, byte[] aad, byte[] iv) throws GeneralSecurityException {
		Cipher cipher = getCipher(true);
		if(iv == null && generateIV && ivLength > 0) {
			iv = generateIV();
		}
		if(iv != null) {
			cipher.init(Cipher.ENCRYPT_MODE, getKey(), getAlgorithmParameterSpec(iv));
		} else {
			cipher.init(Cipher.ENCRYPT_MODE, getKey());
			iv = cipher.getIV();
		}
		ivThreadLocal.set(iv);
		if(aad != null) {
			cipher.updateAAD(aad);
		}
		byte[] encrypted;
		if(prependIV && iv != null) {
			int outputSize = cipher.getOutputSize(message.length);
			encrypted = new byte[iv.length + outputSize];
			System.arraycopy(iv, 0, encrypted, 0, iv.length);
			try {
				int nBytes = cipher.doFinal(message, 0, message.length, encrypted, iv.length);
				if(nBytes < outputSize) {
					int excessBytes = outputSize - nBytes;
					byte[] resized = new byte[encrypted.length - excessBytes];
					System.arraycopy(encrypted, 0, resized, 0, resized.length);
					encrypted = resized;
				}
			} catch (ShortBufferException e) {
				throw new RuntimeException(e);
			}
		} else {
			encrypted = cipher.doFinal(message);
		}
		return encrypted;
	}

	/**
	 * <p>Decrypts a byte array and returns the decrypted message.</p>
	 * @param message
	 * @return
	 * @throws GeneralSecurityException
	 */
	public byte[] decrypt(byte[] message) throws GeneralSecurityException {
		return decrypt(message, null);
	}

	/**
	 * <p>Decrypts a byte array and returns the decrypted message.</p>
	 * @param message
	 * @param aad
	 * @return
	 * @throws GeneralSecurityException
	 */
	public byte[] decrypt(byte[] message, byte[] aad) throws GeneralSecurityException {
		return decrypt(message, aad, null);
	}

	/**
	 * <p>Decrypts a byte array and returns the decrypted message.</p>
	 * @param message
	 * @param aad
	 * @param iv
	 * @return
	 * @throws GeneralSecurityException
	 */
	public byte[] decrypt(byte[] message, byte[] aad, byte[] iv) throws GeneralSecurityException {
		Cipher cipher = getCipher(true);
		if(ivLength > 0) {
			if(prependIV) {
				cipher.init(Cipher.DECRYPT_MODE, getKey(), getAlgorithmParameterSpec(message));
				if(aad != null) {
					cipher.updateAAD(aad);
				}
				return cipher.doFinal(message, ivLength, message.length - ivLength);
			} else {
				throw new IllegalStateException("Could not obtain IV");
			}
		} else {
			if(iv != null) {
				cipher.init(Cipher.DECRYPT_MODE, getKey(), getAlgorithmParameterSpec(iv));
			} else {
				cipher.init(Cipher.DECRYPT_MODE, getKey());
			}
			if(aad != null) {
				cipher.updateAAD(aad);
			}
			return cipher.doFinal(message);
		}
	}

	/**
	 * <p>Returns the last used thread-local initialization vector that was either passed as argument or generated during the last encryption operation.</p>
	 * @return
	 */
	public byte[] getIV() {
		return ivThreadLocal.get();
	}

	/**
	 * <p>Sets whether the initialization vector should be prepended to the encrypted output and can be shifted
	 * off the start of during decryption.</p>
	 * <p>Defaults to <code>true</code> when constructed with an explicit IV length or <code>false</code> when constructed with prespecified IV.</p>
	 * <p><b>Note:</b> This setting also applies when in streaming mode using {@link #wrapInputStream(InputStream)} and {@link #wrapOutputStream(OutputStream)}.</p>
	 * @param prependIV
	 */
	public void setPrependIV(boolean prependIV) {
		this.prependIV = prependIV;
	}

	/**
	 * <p>Sets whether the initialization vector should be generated by this <code>Encryptor</code> instance.</p>
	 * @param generateIV
	 */
	public void setGenerateIV(boolean generateIV) {
		this.generateIV = generateIV;
	}

	/**
	 * <p>Returns the algorithm.</p>
	 * @return
	 */
	public String getAlgorithm() {
		return algorithm;
	}

	/**
	 * <p>Sets the algorithm provider.</p>
	 * @param algorithmProvider
	 */
	public void setAlgorithmProvider(String algorithmProvider) {
		this.algorithmProvider = algorithmProvider;
	}

	/**
	 * <p>Returns the key. This is either the key that this <code>Encryptor</code> has been constructed with or
	 * a key generated by a <code>SecretKeyFactory</code> according to a <code>KeySpec</code>.</p>
	 * @return
	 */
	public Key getKey() {
		if(key != null) {
			return key;
		} else if(keySpec != null && secretKeyFactory != null) {
			try {
				return key = secretKeyFactory.generateSecret(keySpec);
			} catch (InvalidKeySpecException e) {
				throw new RuntimeException(e);
			}
		}
		throw new IllegalStateException("Cannot produce key");
	}

	/**
	 * <p>Wraps an <code>InputStream</code> with a <code>CipherInputStream</code> using this encryptor's cipher.</p>
	 * <p>If an <code>ivLength</code> has been specified and <code>prependIV</code> is set to <code>true</code> this method
	 * will try to read and consume an IV from the <code>InputStream</code> before wrapping it.</p>
	 * @param is
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public CipherInputStream wrapInputStream(InputStream is) throws GeneralSecurityException, IOException {
		return wrapInputStream(is, null);
	}

	/**
	 * <p>Wraps an <code>InputStream</code> with a <code>CipherInputStream</code> using this encryptor's cipher.</p>
	 * <p>If an <code>ivLength</code> has been specified and <code>prependIV</code> is set to <code>true</code> this method
	 * will try to read and consume an IV from the <code>InputStream</code> before wrapping it.</p>
	 * @param is
	 * @param iv
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public CipherInputStream wrapInputStream(InputStream is, byte[] iv) throws GeneralSecurityException, IOException {
		Cipher cipher = getCipher(true);
		if(iv == null && ivLength > 0) {
			if(prependIV) {
				iv = new byte[ivLength];
				is.read(iv);
			} else {
				throw new IllegalStateException("Could not obtain IV");
			}
		}
		if(iv != null) {
			cipher.init(Cipher.DECRYPT_MODE, getKey(), getAlgorithmParameterSpec(iv));
		} else {
			cipher.init(Cipher.DECRYPT_MODE, getKey());
		}
		return new CipherInputStream(is, cipher);
	}

	/**
	 * <p>Wraps an <code>OutputStream</code> with a <code>CipherOutputStream</code> using this encryptor's cipher.</p>
	 * <p>If an <code>ivLength</code> has been specified or an explicit IV has been set during construction
	 * and <code>prependIV</code> is set to <code>true</code> this method will write an IV to the <code>OutputStream</code> before wrapping it.</p>
	 * @param os
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public CipherOutputStream wrapOutputStream(OutputStream os) throws GeneralSecurityException, IOException {
		return wrapOutputStream(os, null);
	}

	/**
	 * <p>Wraps an <code>OutputStream</code> with a <code>CipherOutputStream</code> using this encryptor's cipher.</p>
	 * <p>If an <code>ivLength</code> has been specified or an explicit IV has been set during construction
	 * and <code>prependIV</code> is set to <code>true</code> this method will write an IV to the <code>OutputStream</code> before wrapping it.</p>
	 * @param os
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public CipherOutputStream wrapOutputStream(OutputStream os, byte[] iv) throws GeneralSecurityException, IOException {
		Cipher cipher = getCipher(true);
		if(iv == null && generateIV && ivLength > 0) {
			iv = generateIV();
		}
		if(iv != null) {
			cipher.init(Cipher.ENCRYPT_MODE, getKey(), getAlgorithmParameterSpec(iv));
		} else {
			cipher.init(Cipher.ENCRYPT_MODE, getKey());
			iv = cipher.getIV();
		}
		ivThreadLocal.set(iv);
		if(prependIV && iv != null) {
			os.write(iv);
		}
		return new CipherOutputStream(os, cipher);
	}

	/**
	 * <p>Returns the thread local cipher.</p>
	 * @return
	 * @throws GeneralSecurityException
	 */
	public Cipher getCipher() throws GeneralSecurityException {
		return getCipher(false);
	}

	/**
	 *
	 * @param create
	 * @return
	 * @throws GeneralSecurityException
	 */
	private Cipher getCipher(boolean create) throws GeneralSecurityException {
		Cipher cipher = cipherThreadLocal.get();
		if(cipher == null || create) {
			cipher = createCipher();
			cipherThreadLocal.set(cipher);
		}
		return cipher;
	}

	/**
	 * <p>Creates the cipherThreadLocal</p>
	 * @return
	 */
	private Cipher createCipher() throws GeneralSecurityException {
		if(algorithmProvider != null) {
			return Cipher.getInstance(algorithm, algorithmProvider);
		} else {
			return Cipher.getInstance(algorithm);
		}
	}

	/**
	 * <p>Returns the algorithm parameter specification.</p>
	 * @param ivBuffer
	 * @return
	 */
	private AlgorithmParameterSpec getAlgorithmParameterSpec(byte[] ivBuffer) {
		int length = ivLength == 0  && ivBuffer != null ? ivBuffer.length : ivLength;
		String[] parts = algorithm.split("/");
		if(parts.length > 1 && parts[1].equalsIgnoreCase("GCM")) {
			return new GCMParameterSpec(tLen > 0 ? tLen: 128, ivBuffer, 0, length);
		}
		return new IvParameterSpec(ivBuffer, 0, length);
	}

	/**
	 * <p>Generates an initialization vector.</p>
	 */
	private byte[] generateIV() {
		byte[] iv = new byte[ivLength];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		return iv;
	}
}