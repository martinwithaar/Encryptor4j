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
	private static final String PROVIDER = "BC";
	
	/*
	 * Attributes
	 */
	
	private AlgorithmParameterSpec spec;
	
	/*
	 * Constructor(s)
	 */
	
	/**
	 * <p>Constructs a <code>ECDHPeer</code> instance using elliptic curve <code>curve</code>.</p>
	 * @param curve
	 * @throws GeneralSecurityException 
	 */
	public ECDHPeer(String curve) throws GeneralSecurityException {
		this(ECNamedCurveTable.getParameterSpec(curve));
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
	    this(new ECParameterSpec(new EllipticCurve(new ECFieldFp(p), a, b), new ECPoint(xg, yg), n, h));
	}
	
	/**
	 * <p>Constructs a <code>ECDHPeer</code> instance using an elliptic curve <code>AlgorithmParameterSpec</code>.</p>
	 * @param spec
	 * @throws GeneralSecurityException 
	 */
	public ECDHPeer(AlgorithmParameterSpec spec) throws GeneralSecurityException {
		super(KeyAgreement.getInstance(ALGORITHM));
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
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
	    keyGen.initialize(spec, new SecureRandom());
		return keyGen.generateKeyPair();
	}
}
