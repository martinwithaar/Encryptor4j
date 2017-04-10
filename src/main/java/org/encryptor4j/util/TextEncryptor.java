package org.encryptor4j.util;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.encryptor4j.Encryptor;
import org.encryptor4j.factory.EncryptorFactory;
import org.encryptor4j.factory.KeyFactory;

/**
 *
 * @author Martin
 *
 */
public class TextEncryptor {

	/*
	 * Attributes
	 */

	private Encryptor encryptor;

	/*
	 * Constructor(s)
	 */

	/**
	 * <p>Constructs a default AES <code>TextEncryptor</code> instance using a randomly generated key. Obtain the key by calling {@link #getEncryptor()} and {@link Encryptor#getKey()}.</p>
	 */
	public TextEncryptor() {
		this(KeyFactory.AES.randomKey());
	}

	/**
	 * <p>Constructs a default AES <code>TextEncryptor</code> instance using the given password.</p>
	 * @param password the password used for encryption
	 */
	public TextEncryptor(String password) {
		this(KeyFactory.AES.keyFromPassword(password.toCharArray()));
	}

	/**
	 * <p>Constructs a default AES <code>TextEncryptor</code> instance using the given AES key.</p>
	 * @param key the key used for encryption
	 */
	public TextEncryptor(Key key) {
		this(EncryptorFactory.AES.messageEncryptor(key));
	}

	/**
	 * <p>Constructs a <code>TextEncryptor</code> instance using the given <code>Encryptor</code>.</p>
	 * @param encryptor the encryptor used for encryption
	 */
	public TextEncryptor(Encryptor encryptor) {
		this.encryptor = encryptor;
	}

	/*
	 * Class methods
	 */

	/**
	 * <p>Encrypts and Base64 encodes a message.</p>
	 * @param message the message
	 * @return the encrypted message
	 * @throws GeneralSecurityException
	 */
	public String encrypt(String message) throws GeneralSecurityException {
		byte[] bytes = encryptor.encrypt(message.getBytes());
		return Base64.getEncoder().encodeToString(bytes);
	}

	/**
	 * <p>Base64 decodes and decrypts an encrypted message.</p>
	 * @param message an encrypted message
	 * @return the decrypted message
	 * @throws GeneralSecurityException
	 */
	public String decrypt(String message) throws GeneralSecurityException {
		byte[] bytes = Base64.getDecoder().decode(message);
		return new String(encryptor.decrypt(bytes));
	}

	/**
	 * <p>Returns the encryptor.</p>
	 * @return
	 */
	public Encryptor getEncryptor() {
		return encryptor;
	}

	/*
	 * Static methods
	 */

	/**
	 *
	 * @param args
	 */
	public static void main(String[] args) {
		Options options = new Options();
		options.addOption(
			Option.builder("t")
				.longOpt("text")
				.hasArg()
				.argName("text")
				.desc("message text")
				.required()
				.build()
		);

		options.addOption(
			Option.builder("d")
				.longOpt("decrypt")
				.desc("decrypt")
				.build()
		);

		options.addOption(
			Option.builder("p")
				.longOpt("password")
				.hasArg()
				.argName("password")
				.desc("password")
				.build()
		);

		options.addOption(
			Option.builder("k")
				.longOpt("key")
				.hasArg()
				.argName("key")
				.desc("Base64 encoded key")
				.build()
		);

		if(args != null && args.length > 0) {
			CommandLineParser parser = new DefaultParser();
			CommandLine cmd;
			try {
				cmd = parser.parse(options, args);
			} catch (ParseException e) {
				throw new RuntimeException("Could not parse args", e);
			}

			String text = cmd.getOptionValue("t");

			TextEncryptor te;
			if(cmd.hasOption("p")) {
				te = new TextEncryptor(cmd.getOptionValue("p"));
			} else if(cmd.hasOption("k")) {
				String encodedKey = cmd.getOptionValue("k");
				byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
				Key key = new SecretKeySpec(keyBytes, "AES");
				te = new TextEncryptor(key);
			} else {
				te = new TextEncryptor();
				byte[] keyBytes = te.getEncryptor().getKey().getEncoded();
				String encodedKey = Base64.getEncoder().encodeToString(keyBytes);
				System.out.println("Base64 encoded key: " + encodedKey);
			}
			try {
				if(cmd.hasOption("d")) {
					String decrypted = te.decrypt(text);
					System.out.println("Decrypted message:");
					System.out.println(decrypted);
				} else {
					String encrypted = te.encrypt(text);
					System.out.println("Encrypted message:");
					System.out.println(encrypted);
				}
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
			}
		} else {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp(TextEncryptor.class.getSimpleName(), options);
		}
		System.exit(0);
	}
}
