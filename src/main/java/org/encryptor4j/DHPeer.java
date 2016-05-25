package org.encryptor4j;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

/**
 * <p><code>KeyAgreementPeer</code> implementation that uses the Diffie-Hellman key agreement protocol.</p>
 * @author Martin
 *
 */
public class DHPeer extends KeyAgreementPeer {
	
	private static final String ALGORITHM = "DH";
	
	/*
	 * Attributes
	 */
	
	private BigInteger p;
	private BigInteger g;
	
	/*
	 * Constructor(s)
	 */
	
	/**
	 * <p>Constructs a <code>DHPeer</code> instance using primes <code>p</code> and <code>g</code>.</p>
	 * <p><b>Note:</b> Use {@link BigInteger#probablePrime(int, java.util.Random)} to create good <code>p</code> and <code>g</code> candidates.</p>
	 * @param p
	 * @param g
	 * @throws GeneralSecurityException 
	 */
	public DHPeer(BigInteger p, BigInteger g) throws GeneralSecurityException {
		this(p, g, null);
	}
	
	/**
	 * <p>Constructs a <code>DHPeer</code> instance using primes <code>p</code> and <code>g</code>.</p>
	 * <p><b>Note:</b> Use {@link BigInteger#probablePrime(int, java.util.Random)} to create good <code>p</code> and <code>g</code> candidates.</p>
	 * @param p
	 * @param g
	 * @throws GeneralSecurityException 
	 */
	public DHPeer(BigInteger p, BigInteger g, String provider) throws GeneralSecurityException {
		super(provider != null ? KeyAgreement.getInstance(ALGORITHM, provider) : KeyAgreement.getInstance(ALGORITHM));
		this.p = p;
		this.g = g;
		initialize();
	}
	
	/*
	 * Class methods
	 */
	
	/**
	 * <p>Returns prime <code>p</code>.</p>
	 * @return
	 */
	public BigInteger getP() {
		return p;
	}
	
	/**
	 * <p>Returns prime <code>g</code>.</p>
	 * @return
	 */
	public BigInteger getG() {
		return g;
	}
	
	/*
	 * Concrete methods
	 */
	
	@Override
	protected KeyPair createKeyPair() throws GeneralSecurityException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM, getKeyAgreement().getProvider());
	    keyGen.initialize(new DHParameterSpec(p, g), new SecureRandom());
		return keyGen.generateKeyPair();
	}
}
