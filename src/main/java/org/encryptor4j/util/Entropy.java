package org.encryptor4j.util;

/**
 *
 * @author Martin
 *
 */
public class Entropy {

	private Entropy() {
	}

	/**
	 * <p>Calculates and returns the Shannon entropy of the given byte array.</p>
	 * <p>The returned value is a value between <code>0</code> and <code>1</code> where
	 * a value of <code>0</code> signifies no entropy and a value of <code>1</code> maximum entropy.</p>
	 * <p>This method may be used to assess the entropy of randomly generated key material but is in no way
	 * by itself a reliable indicator of true randomness.</p>
	 * <p>It indicates distribution entropy as opposed to sequence entropy.</p>
	 * @param bytes
	 * @return
	 */
	public static final double shannon(byte[] bytes) {
		int n = bytes.length;
		long[] values = new long[256];
		for(int i = 0; i < n; i++) {
			values[bytes[i] - Byte.MIN_VALUE]++;
		}
		double entropy = 0;
		double p;
		double log256 = Math.log(256);
		for(long count : values) {
			if(count != 0) {
				p = (double) count / n;
				entropy -= p * (Math.log(p) / log256);
			}
		}
		return entropy;
	}

	/**
	 *
	 * @param bytes
	 * @return
	 */
	public static final double shannonSequence(byte[] bytes) {
		byte[] diffs = new byte[bytes.length - 1];
		for(int i = 0, n = diffs.length; i < n; i++) {
			diffs[i] = (byte) (bytes[i + 1] - bytes[i]);
		}
		return shannon(diffs);
	}
}
