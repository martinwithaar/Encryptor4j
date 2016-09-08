package org.encryptor4j.test;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Security;

import javax.crypto.SecretKey;

import org.apache.commons.io.FileUtils;
import org.encryptor4j.Encryptor;
import org.junit.Test;

/**
 * <p>Unit test that tests AES streaming encryption with the <code>Encryptor</code> class.</p>
 * @author Martin
 *
 */
public class StreamTest {
	
	private static final String FILENAME = "test_picture.jpg";
	private static final String FILENAME_ENCRYPTED = "test_picture.jpg.encrypted";
	private static final String FILENAME_DECRYPTED = "test_picture_stream.jpg";
	private static final int AES_KEY_SIZE = 256;
	private static final int AES_IV_SIZE = 16;
	private static final int DES_KEY_SIZE = 64;
	private static final int DES_IV_SIZE = 8;
	private static final int BUFFER_SIZE = 4 * 1024;

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	@Test public void testAES_CTR() throws GeneralSecurityException, IOException {
		SecretKey secretKey = Encryptor.generateSecretKey("AES", AES_KEY_SIZE);
		Encryptor encryptor = new Encryptor(secretKey, "AES/CTR/NoPadding", AES_IV_SIZE);
		encryptor.setAlgorithmProvider("BC");
		
		InputStream is = null;
		OutputStream os = null;
		try {
			is = new FileInputStream(FILENAME);
			os = encryptor.wrapOutputStream(new FileOutputStream(FILENAME_ENCRYPTED));
			byte[] buffer = new byte[BUFFER_SIZE];
			int nRead;
			while((nRead = is.read(buffer)) != -1) {
				os.write(buffer, 0, nRead);
			}
			os.flush();
		} finally {
			if(is != null) {
				is.close();
			}
			if(os != null) {
				os.close();
			}
		}
		
		try {
			encryptor = new Encryptor(secretKey, "AES/CTR/NoPadding", AES_IV_SIZE);
			encryptor.setAlgorithmProvider("BC");
			is = encryptor.wrapInputStream(new FileInputStream(FILENAME_ENCRYPTED));
			os = new FileOutputStream(FILENAME_DECRYPTED);
			byte[] buffer = new byte[BUFFER_SIZE];
			int nRead;
			while((nRead = is.read(buffer)) != -1) {
				os.write(buffer, 0, nRead);
			}
			os.flush();
		} finally {
			if(is != null) {
				is.close();
			}
			if(os != null) {
				os.close();
			}
		}
		
		assertTrue(FileUtils.contentEquals(new File(FILENAME), new File(FILENAME_DECRYPTED)));
    }
	
	@Test public void testDES_CTR() throws GeneralSecurityException, IOException {
		SecretKey key = Encryptor.generateSecretKey("DES", DES_KEY_SIZE);
		Encryptor encryptor = new Encryptor(key, "DES/CTR/NoPadding", DES_IV_SIZE);
		encryptor.setAlgorithmProvider("BC");
		
		InputStream is = null;
		OutputStream os = null;
		try {
			is = new FileInputStream(FILENAME);
			os = encryptor.wrapOutputStream(new FileOutputStream(FILENAME_ENCRYPTED));
			byte[] buffer = new byte[BUFFER_SIZE];
			int nRead;
			while((nRead = is.read(buffer)) != -1) {
				os.write(buffer, 0, nRead);
			}
			os.flush();
		} finally {
			if(is != null) {
				is.close();
			}
			if(os != null) {
				os.close();
			}
		}
		
		try {
			encryptor = new Encryptor(key, "DES/CTR/NoPadding", DES_IV_SIZE);
			encryptor.setAlgorithmProvider("BC");
			is = encryptor.wrapInputStream(new FileInputStream(FILENAME_ENCRYPTED));
			os = new FileOutputStream(FILENAME_DECRYPTED);
			byte[] buffer = new byte[BUFFER_SIZE];
			int nRead;
			while((nRead = is.read(buffer)) != -1) {
				os.write(buffer, 0, nRead);
			}
			os.flush();
		} finally {
			if(is != null) {
				is.close();
			}
			if(os != null) {
				os.close();
			}
		}
		
		assertTrue(FileUtils.contentEquals(new File(FILENAME), new File(FILENAME_DECRYPTED)));
    }
}
