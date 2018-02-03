package org.encryptor4j.test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import org.encryptor4j.util.Entropy;
import org.junit.Test;

public class JitterTest {

	@Test
	public void testJitter() {
		Thread thread = new Thread(new JitterRunnable());
		thread.start();

		synchronized(this) {
			try {
				wait();
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}


	private class JitterRunnable implements Runnable {

		@Override
		public void run() {
			byte[] totalBytes = new byte[1024];
			ByteBuffer totalBuffer = ByteBuffer.wrap(totalBytes);
			byte[] longBytes = new byte[8];

			ByteBuffer longBuffer = ByteBuffer.wrap(longBytes);
			int n = totalBytes.length / 2;
			for(int i = 0; i < n; i++) {
				long sleepTime = 10;
				long start = System.nanoTime();
				try {
					Thread.sleep(sleepTime);
				} catch (InterruptedException e) {
				}
				long duration = System.nanoTime() - start;
				long delta = duration - sleepTime * 1000000L;
				//System.out.println(delta);
				longBuffer.putLong(0, delta);
				System.out.println(Arrays.toString(longBytes));

				totalBuffer.put(longBytes[6]);
				totalBuffer.put(longBytes[7]);
			}

			System.out.println("Distribution entropy: " + Entropy.shannon(totalBytes));
			System.out.println("Sequence entropy: " + Entropy.shannonSequence(totalBytes));

			Random random = new SecureRandom();
			random.nextBytes(totalBytes);

			System.out.println("Distribution entropy: " + Entropy.shannon(totalBytes));
			System.out.println("Sequence entropy: " + Entropy.shannonSequence(totalBytes));

			for(int i = 0; i < totalBytes.length; i++) {
				totalBytes[i] = (byte) ((i % 256) + Byte.MIN_VALUE);
			}

			System.out.println("Distribution entropy: " + Entropy.shannon(totalBytes));
			System.out.println("Sequence entropy: " + Entropy.shannonSequence(totalBytes));

			synchronized(JitterTest.this) {
				JitterTest.this.notify();
			}
		}

	}
}

