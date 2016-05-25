package org.encryptor4j;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;

import javax.crypto.KeyAgreement;

/**
 * <p>Abstract key agreement peer class.</p>
 * @author Martin
 *
 */
public abstract class KeyAgreementPeer {
	
	/*
	 * Attributes
	 */

	private KeyAgreement keyAgreement;
	private KeyPair keyPair;
	
	/*
	 * Constructor(s)
	 */
	
	/**
	 * <p>Constructs a key agreement peer.</p>
	 * @param keyAgreement
	 * @throws GeneralSecurityException
	 */
	public KeyAgreementPeer(KeyAgreement keyAgreement) throws GeneralSecurityException {
		this.keyAgreement = keyAgreement;
	}
	
	/*
	 * Abstract methods
	 */
	
	/**
	 * <p>Creates this peer's key pair.</p>
	 * @return
	 * @throws GeneralSecurityException
	 */
	protected abstract KeyPair createKeyPair() throws GeneralSecurityException;
	
	/*
	 * Class methods
	 */
	
	/**
	 * <p>Creates a keypair and initializes the key agreement.</p>
	 * @throws GeneralSecurityException 
	 * 
	 */
	protected void initialize() throws GeneralSecurityException {
		this.keyPair = createKeyPair();
		this.keyAgreement.init(keyPair.getPrivate());
	}
	
	/**
	 * <p>Computes the shared secret using the other peer's public key.</p>
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 */
	public byte[] computeSharedSecret(Key key) throws InvalidKeyException {
		keyAgreement.doPhase(key, true);
		return keyAgreement.generateSecret();
	}
	
	/**
	 * <p>Returns this peer's public key.</p>
	 * @return
	 */
	public Key getPublicKey() {
		return keyPair.getPublic();
	}
	
	/**
	 * <p>Returns this peer's <code>KeyAgreement</code> instance.</p>
	 * @return
	 */
	public KeyAgreement getKeyAgreement() {
		return keyAgreement;
	}
}
