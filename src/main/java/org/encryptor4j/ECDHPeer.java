package org.encryptor4j;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.ECNamedCurveTable;

/**
 * <p><code>KeyAgreementPeer</code> implementation that uses the Elliptic Curve Diffie-Hellman key agreement protocol.</p>
 * @author Martin
 *
 */
public class ECDHPeer extends KeyAgreementPeer {
	
	private static final String ALGORITHM = "ECDH";
	
	/*
	 * Attributes
	 */
	
	private AlgorithmParameterSpec spec;
	
	/*
	 * Constructor(s)
	 */
	
	/**
	 * <p>Constructs a <code>ECDHPeer</code> instance using a named elliptic curve <code>curve</code>.</p>
	 * <p><b>Note:</b> This constructor will use Bouncy Castle (BC) as its provider.</p>
	 * @param curve
	 * @throws GeneralSecurityException 
	 */
	public ECDHPeer(String curve) throws GeneralSecurityException {
		this(ECNamedCurveTable.getParameterSpec(curve), "BC");
	}
	
	/**
	 * <p>Constructs a <code>ECDHPeer</code> instance using a custom elliptic curve.</p>
	 * @param p
	 * @param a
	 * @param b
	 * @param xg
	 * @param yg
	 * @param n
	 * @param h
	 * @throws GeneralSecurityException 
	 */
	public ECDHPeer(BigInteger p, BigInteger a, BigInteger b, BigInteger xg, BigInteger yg, BigInteger n, int h) throws GeneralSecurityException {
	    this(new ECParameterSpec(new EllipticCurve(new ECFieldFp(p), a, b), new ECPoint(xg, yg), n, h), null);
	}
	
	/**
	 * <p>Constructs a <code>ECDHPeer</code> instance using an elliptic curve <code>AlgorithmParameterSpec</code>.</p>
	 * @param spec
	 * @throws GeneralSecurityException 
	 */
	public ECDHPeer(AlgorithmParameterSpec spec) throws GeneralSecurityException {
		this(spec, null);
	}
	
	/**
	 * <p>Constructs a <code>ECDHPeer</code> instance using an elliptic curve <code>AlgorithmParameterSpec</code> and a custom provider.</p>
	 * @param spec
	 * @param provider
	 * @throws GeneralSecurityException 
	 */
	public ECDHPeer(AlgorithmParameterSpec spec, String provider) throws GeneralSecurityException {
		super(provider != null ? KeyAgreement.getInstance(ALGORITHM, provider) : KeyAgreement.getInstance(ALGORITHM));
		this.spec = spec;
		initialize();
	}
	
	/*
	 * Class methods
	 */
	
	/**
	 * <p>Returns the inner <code>AlgorithmParameterSpec</code>.</p>
	 * @return
	 */
	public AlgorithmParameterSpec getAlgorithmParameterSpec() {
		return spec;
	}
	
	/*
	 * Concrete methods
	 */
	
	@Override
	protected KeyPair createKeyPair() throws GeneralSecurityException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM, getKeyAgreement().getProvider());
	    keyGen.initialize(spec, new SecureRandom());
		return keyGen.generateKeyPair();
	}
}
