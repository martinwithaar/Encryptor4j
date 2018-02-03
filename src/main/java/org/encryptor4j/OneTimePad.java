package org.encryptor4j;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * <p>One-time pad implementation.</p>
 *
 * <p></p>
 * @author Martin
 *
 */
public class OneTimePad {

	/*
	 * Attributes
	 */

	private SecureRandom random;
	private int ioBufferSize;
	private int workBufferSize;
	private boolean zeroFill;

	/*
	 * Constructor(s)
	 */

	/**
	 * <p>Constructs a default <code>OneTimePad</code> instance.</p>
	 */
	public OneTimePad() {
		this(1024 * 1024, 256 * 1024);
	}

	/**
	 * <p>Constructs a <code>OneTimePad</code> instance with custom buffer sizes.</p>
	 * @param ioBufferSize
	 * @param workBufferSize
	 */
	public OneTimePad(int ioBufferSize, int workBufferSize) {
		this(new SecureRandom(), ioBufferSize, workBufferSize);
	}

	/**
	 * <p>Constructs a <code>OneTimePad</code> instance with custom random source and buffer sizes.</p>
	 * @param random
	 * @param ioBufferSize
	 * @param workBufferSize
	 */
	public OneTimePad(SecureRandom random, int ioBufferSize, int workBufferSize) {
		this.random = random;
		this.ioBufferSize = ioBufferSize;
		this.workBufferSize = workBufferSize;
	}

	/*
	 * Class methods
	 */

	/**
	 * <p>Creates a padfile containing random bytes.</p>
	 * @param padFile
	 * @param size
	 */
	public void createPadFile(File padFile, long size) {
		OutputStream os = null;
		try {
			os = new BufferedOutputStream(new FileOutputStream(padFile), ioBufferSize);
			long totalSize = 0;
			long bytesLeft;
			byte[] randomBytes = new byte[workBufferSize];
			while (totalSize < size) {
				random.nextBytes(randomBytes);
				bytesLeft = size - totalSize;
				if(bytesLeft < workBufferSize) {
					os.write(randomBytes, 0, (int) bytesLeft);
					totalSize += bytesLeft;
				} else {
					os.write(randomBytes);
					totalSize += workBufferSize;
				}
			}
			os.flush();
		} catch(IOException e) {
			throw new RuntimeException(e);
		} finally {
			if(os != null) {
				try {
					os.close();
				} catch(IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * <p>Reads bytes from <code>inFile</code>, pads them with corresponding offset bytes from <code>padFile</code>
	 * and writes them to <code>outFile</code>.</p>
	 * <p>Returns the new offset for the pad file.</p>
	 * @param inFile
	 * @param outFile
	 * @param padFile
	 * @param offset
	 * @return
	 */
	public long padData(File inFile, File outFile, File padFile, long offset) {
		RandomAccessFile raf = null;
		InputStream is = null;
		OutputStream os = null;
		try {
			raf = new RandomAccessFile(padFile, zeroFill ? "rw" : "r");
			raf.seek(offset);

			is = new BufferedInputStream(new FileInputStream(inFile), ioBufferSize);
			os = new BufferedOutputStream(new FileOutputStream(outFile), ioBufferSize);

			byte[] padBytes = new byte[workBufferSize];
			byte[] bytes = new byte[workBufferSize];
			int nPadBytes;
			int nBytes;

			while(true) {
				nBytes = is.read(bytes);
				nPadBytes = raf.read(padBytes);
				if(nBytes > 0) {
					if(nPadBytes >= nBytes) {
						for(int i = 0; i < nBytes; i++) {
							// Work the magic
							bytes[i] = (byte) (bytes[i] ^ padBytes[i]);
						}
						os.write(bytes, 0, nBytes);

						if(zeroFill) {
							// Perform zero-filling
							raf.seek(offset);
							for(int i = 0; i < nBytes; i++) {
								raf.write(0);
							}
						}
						offset += nBytes;
					} else {
						throw new IOException("Not enough pad bytes");
					}
				} else {
					break;
				}
			}
			os.flush();
			return offset;
		} catch(IOException e) {
			throw new RuntimeException(e);
		} finally {
			if(raf != null) {
				try {
					raf.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
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
		}
	}

	/**
	 * <p>Sets whether padding bytes should be set to <code>0</code> when they have been used.
	 * This potentially increases security because the message can only be padded and unpadded once.</p>
	 * @param zeroFill
	 */
	public void setZeroFill(boolean zeroFill) {
		this.zeroFill = zeroFill;
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
			Option.builder("c")
				.longOpt("create")
				.hasArg()
				.argName("file")
				.desc("create pad file")
				.build()
		);

		options.addOption(
			Option.builder("p")
				.longOpt("pad")
				.hasArg()
				.argName("file")
				.desc("pad file")
				.build()
		);

		options.addOption(
			Option.builder("f")
				.longOpt("offset")
				.hasArg()
				.argName("bytes")
				.desc("offset")
				.build()
		);

		options.addOption(
			Option.builder("s")
				.longOpt("size")
				.hasArg()
				.argName("bytes")
				.desc("size")
				.build()
		);

		options.addOption(
			Option.builder("i")
				.longOpt("in-file")
				.hasArg()
				.argName("file")
				.desc("input file")
				.build()
		);

		options.addOption(
			Option.builder("o")
				.longOpt("out-file")
				.hasArg()
				.argName("file")
				.desc("output file")
				.build()
		);

		options.addOption(
			Option.builder("z")
				.longOpt("zerofill")
				.desc("overwrite used padding with 0s")
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
			OneTimePad otp = new OneTimePad();
			if(cmd.hasOption("c")) {
				File padFile = new File(cmd.getOptionValue("c"));
				long size = Long.parseLong(cmd.getOptionValue("s"));
				System.out.println("Creating pad file...");
				otp.createPadFile(padFile, size);
				System.out.println("Done! " + size + " random bytes successfully written to " + padFile);
			} else if(cmd.hasOption("i") && cmd.hasOption("o") && cmd.hasOption("p")) {
				File inFile = new File(cmd.getOptionValue("i"));
				File outFile = new File(cmd.getOptionValue("o"));
				File padFile = new File(cmd.getOptionValue("p"));
				long offset = cmd.hasOption("f") ? Long.valueOf(cmd.getOptionValue("f")) : 0L;
				otp.setZeroFill(cmd.hasOption("z"));
				System.out.println("Padding data...");
				offset = otp.padData(inFile, outFile, padFile, offset);
				System.out.println("Done! New padding offset: " + offset);
			} else {
				HelpFormatter formatter = new HelpFormatter();
				formatter.printHelp(OneTimePad.class.getSimpleName(), options);
			}
		} else {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp(OneTimePad.class.getSimpleName(), options);
		}
		System.exit(0);
	}
}
