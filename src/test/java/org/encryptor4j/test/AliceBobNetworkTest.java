package org.encryptor4j.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.Security;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.FileUtils;
import org.encryptor4j.ECDHPeer;
import org.encryptor4j.Encryptor;
import org.encryptor4j.KeyAgreementPeer;

import static org.junit.Assert.*;
import org.junit.Test;

/**
 * <p>Unit test that performs a key agreement with a server over a TCP socket and sends a file to the server encrypted using the agreed shared secret.</p>
 * @see https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
 * @author Martin
 *
 */
public class AliceBobNetworkTest {

	private static final String FILENAME = "test_picture.jpg";
	private static final String FILENAME_RECEIVED = "test_picture_network.jpg";
	private static final int BUFFER_SIZE = 4 * 1024;
	private static final int PORT = 1337;
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	@Test public void testECDH() throws GeneralSecurityException {

		Runnable serverRunnable = new ServerRunnable();
		Thread thread = new Thread(serverRunnable);
		thread.start();

		// Wait until server is set up
		synchronized(serverRunnable) {
			try {
				serverRunnable.wait();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

		Socket socket = null;
		InputStream is = null;
		OutputStream os = null;
		FileInputStream fis = null;
		try {
			socket = new Socket((String) null, PORT);
			is = socket.getInputStream();

			// Wait for input to arrive
			while(is.available() == 0) {
				try {
					Thread.sleep(10);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
			// Read curve
			ObjectInputStream ois = new ObjectInputStream(is);
			String curve = ois.readUTF();

			// Read Bob's public key
			Key publicKey = (Key) ois.readObject();

			// Create ECDH peer
			KeyAgreementPeer alice = new ECDHPeer(curve);

			// Send Alice's public key
			os = socket.getOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(os);
			oos.writeObject(alice.getPublicKey());
			oos.flush();

			// Compute shared secret
			byte[] sharedSecret = alice.computeSharedSecret(publicKey);

			// Create encryptor
			SecretKey secretKey = new SecretKeySpec(sharedSecret, "AES");
			Encryptor encryptor = new Encryptor(secretKey, "AES/CTR/NoPadding", 16);

			// Stream file using encryption
			CipherOutputStream cos = encryptor.wrapOutputStream(os);
			fis = new FileInputStream(FILENAME);
			byte[] buffer = new byte[BUFFER_SIZE];
			int nRead;
			while((nRead = fis.read(buffer)) != -1) {
				cos.write(buffer, 0, nRead);
			}
			cos.flush();
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} finally {
			if(is != null) {
				try {
					is.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if(os != null) {
				try {
					os.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if(socket != null) {
				try {
					socket.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if(fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		// Wait until server is finished
		synchronized(serverRunnable) {
			try {
				serverRunnable.wait();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

		try {
			// Check if the received file equals the original
			assertTrue(FileUtils.contentEquals(new File(FILENAME), new File(FILENAME_RECEIVED)));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * <p>Runnable that represents the server named Bob that receives the file.</p>
	 * @author Martin
	 *
	 */
	private static class ServerRunnable implements Runnable {

		private static final String CURVE = "brainpoolp256r1";

		@Override
		public void run() {
			ServerSocket serverSocket = null;
			InputStream is = null;
			OutputStream os = null;
			FileOutputStream fos = null;
			try {
				// Create server socket & accept
				serverSocket = new ServerSocket(PORT);

				// Notify that the server is setup
				synchronized(this) {
					notify();
				}

				// Accept incoming connections
				Socket clientSocket = serverSocket.accept();

				// Create ECDH peer
				KeyAgreementPeer bob = new ECDHPeer(CURVE);

				// Send Bob's curve
				os = clientSocket.getOutputStream();
				ObjectOutputStream oos = new ObjectOutputStream(os);
				oos.writeUTF(CURVE);
				oos.flush();

				// Send Bob's public key
				oos.writeObject(bob.getPublicKey());
				oos.flush();

				// Wait for input to arrive
				is = clientSocket.getInputStream();
				while(is.available() == 0) {
					try {
						Thread.sleep(10);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
				// Read Alice's public key
				ObjectInputStream ois = new ObjectInputStream(is);
				Key publicKey = (Key) ois.readObject();

				// Compute shared secret
				byte[] sharedSecret = bob.computeSharedSecret(publicKey);

				// Create decryptor
				SecretKey secretKey = new SecretKeySpec(sharedSecret, "AES");
				Encryptor decryptor = new Encryptor(secretKey, "AES/CTR/NoPadding", 16);

				// Receive encrypted file
				CipherInputStream cis = decryptor.wrapInputStream(is);
				fos = new FileOutputStream(FILENAME_RECEIVED);
				byte[] buffer = new byte[BUFFER_SIZE];
				int nRead;
				while((nRead = cis.read(buffer)) != -1) {
					fos.write(buffer, 0, nRead);
				}
			} catch (IOException e) {
				e.printStackTrace();
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} finally {
				if(is != null) {
					try {
						is.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				if(os != null) {
					try {
						os.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				if(serverSocket != null) {
					try {
						serverSocket.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				if(fos != null) {
					try {
						fos.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}

			// Notify that the server is finished
			synchronized(this) {
				notify();
			}
		}
	}
}
