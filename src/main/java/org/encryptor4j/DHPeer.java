package org.encryptor4j;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

/**
 * 
 * @author Martin
 *
 */
public class DHPeer extends KeyAgreementPeer {
	
	private static final String ALGORITHM = "DH";
	private static final String PROVIDER = "BC";
	
	/*
	 * Attributes
	 */
	
	private BigInteger p;
	private BigInteger g;
	
	/*
	 * Constructor(s)
	 */
	
	/**
	 * 
	 * @param p
	 * @param g
	 * @throws GeneralSecurityException 
	 */
	public DHPeer(BigInteger p, BigInteger g) throws GeneralSecurityException {
		super(KeyAgreement.getInstance(ALGORITHM, PROVIDER));
		this.p = p;
		this.g = g;
		initialize();
	}
	
	/*
	 * Concrete methods
	 */
	
	@Override
	protected KeyPair createKeyPair() throws GeneralSecurityException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
	    keyGen.initialize(new DHParameterSpec(p, g), new SecureRandom());
		return keyGen.generateKeyPair();
	}
}
