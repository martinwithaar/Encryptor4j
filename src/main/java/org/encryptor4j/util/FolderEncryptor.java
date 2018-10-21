package org.encryptor4j.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

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
 * <p>Class for encrypting and decrypting files.</p>
 * @author Martin
 *
 */
public class FolderEncryptor {

    /*
     * Attributes
     */

    private Encryptor encryptor;
    private int bufferSize;

    /*
     * Constructor(s)
     */

    /**
     * <p>Constructs a default AES <code>FileEncryptor</code> instance using a randomly generated key. Obtain the key by calling {@link #getEncryptor()} and {@link Encryptor#getKey()}.</p>
     */
    public FolderEncryptor() {
        this(KeyFactory.AES.randomKey());
    }

    /**
     * <p>Constructs a default AES <code>FileEncryptor</code> instance using the given password.</p>
     * @param password the password used for encryption/decryption
     */
    public FolderEncryptor(String password) {
        this(KeyFactory.AES.keyFromPassword(password.toCharArray()));
    }

    /**
     * <p>Constructs a default AES <code>FileEncryptor</code> instance using the given AES key.</p>
     * @param key the key used for encryption/decryption
     */
    public FolderEncryptor(Key key) {
        this(EncryptorFactory.AES.streamEncryptor(key));
    }

    /**
     * <p>Constructs a default <code>FileEncryptor</code> instance using the given <code>Encryptor</code>.</p>
     * @param encryptor the encryptor used for encryption/decryption
     */
    public FolderEncryptor(Encryptor encryptor) {
        super();
        this.encryptor = encryptor;
        this.bufferSize = 65536;
    }

    /*
     * Class methods
     */

    /**
     * <p>Reads and encrypts file <code>src</code> and writes the encrypted result to file <code>dest</code>.</p>
     * @param src the source file
     * @param dest the destination file
     * @param src
     * @param dest
     * @throws FileNotFoundException
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public void encrypt(File src, File dest) throws GeneralSecurityException, IOException {
        InputStream is = null;
        OutputStream os = null;
        File zipFile = null;
        try {
            zipFile = zipDirectory(src);
            is = new FileInputStream(zipFile);
            os = encryptor.wrapOutputStream(new FileOutputStream(dest));
            copy(is, os);
        } finally {
            if(is != null) {
                is.close();
            }
            if(os != null) {
                os.close();
            }
            zipFile.delete();
        }
    }

    /**
     * <p>Reads and decrypts file <code>src</code> and writes the decrypted result to file <code>dest</code>.</p>
     * @param src the source file
     * @param dest the destination file
     * @throws FileNotFoundException
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public void decrypt(File src, File dest) throws GeneralSecurityException, IOException {
        InputStream is = null;
        OutputStream os = null;
        File unZipFile = null;
        try {
            unZipFile = new File(dest.getPath()+".zip");
            is = encryptor.wrapInputStream(new FileInputStream(src));
            os = new FileOutputStream(unZipFile);
            copy(is, os);
            unZipDirectory(unZipFile);
        } finally {
            if(is != null) {
                is.close();
            }
            if(os != null) {
                os.close();
            }
            unZipFile.delete();
        }
    }

    /**
     * <p>Reads data from the <code>InputStream</code> and writes it to the <code>OutputStream</code>.</p>
     * @param is the input stream
     * @param os the output stream
     * @throws IOException
     */
    private void copy(InputStream is, OutputStream os) throws IOException {
        byte[] buffer = new byte[bufferSize];
        int nRead;
        while((nRead = is.read(buffer)) != -1) {
            os.write(buffer, 0, nRead);
        }
        os.flush();
    }

    /**
     * <p>A wrapper around <code>zipFile</code> method.</p>
     * @param src the source file
     * @return the resultant file object after zipping
     */
    private File zipDirectory(File src) {

        FileOutputStream fos = null;
        ZipOutputStream zipOut = null;
        try {
            fos = new FileOutputStream(src.getPath()+".zip");
            zipOut = new ZipOutputStream(fos);
            zipFile(src, zipOut);
            zipOut.close();
            fos.close();
        } finally {
            return new File(src.getPath()+".zip");
        }
    }

    /**
     * <p>Converts the directory into a zip file so that it can be later processed by <code>encryptor</code>.</p>
     * @param fileToZip the source file
     * @param zipOut the zip output stream
     * @throws IOException
     */
    private void zipFile(File fileToZip, ZipOutputStream zipOut) throws IOException {
        if (fileToZip.isHidden()) {
            return;
        }
        if (fileToZip.isDirectory()) {
            File[] children = fileToZip.listFiles();
            for (File childFile : children) {
                zipFile(childFile, zipOut);
            }
            return;
        }
        FileInputStream fis = new FileInputStream(fileToZip);
        ZipEntry zipEntry = new ZipEntry(fileToZip.getName());
        zipOut.putNextEntry(zipEntry);
        byte[] bytes = new byte[1024];
        int length;
        while ((length = fis.read(bytes)) >= 0) {
            zipOut.write(bytes, 0, length);
        }
        fis.close();
    }

    /**
     * <p>Wrapper around <code>unZipFile</code> method.</p>
     * @param unZipFile file that is to be unzipped
     * @throws IOException
     */
    private void unZipDirectory(File unZipFile) throws IOException {

        String path = unZipFile.getPath();
        File directory = new File(path.substring(0,path.length()-4));
        if (!directory.exists()){
            directory.mkdirs();
        }
        unZipFile(unZipFile, directory.getPath());
    }

    /**
     * <p>Unzips the file.</p>
     * @param fileToUnZip File that is to be unzipped
     * @throws IOException
     */
    private void unZipFile(File fileToUnZip, String path) throws IOException {

        byte[] buffer = new byte[1024];
        ZipInputStream zis = new ZipInputStream(new FileInputStream(fileToUnZip));
        ZipEntry zipEntry = zis.getNextEntry();
        while(zipEntry != null){
            String fileName = zipEntry.getName();
            File newFile = new File(path+"\\"+fileName);
            FileOutputStream fos = new FileOutputStream(newFile);
            int len;
            while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fos.close();
            zipEntry = zis.getNextEntry();
        }
        zis.closeEntry();
        zis.close();
    }

    /**
     * <p>Returns the encryptor.</p>
     * @return
     */
    public Encryptor getEncryptor() {
        return encryptor;
    }

    /**
     * <p>Returns the buffer size.</p>
     * @return
     */
    public int getBufferSize() {
        return bufferSize;
    }

    /**
     * <p>Sets the buffer size.</p>
     * @param bufferSize the buffer size
     */
    public void setBufferSize(int bufferSize) {
        this.bufferSize = bufferSize;
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
                Option.builder("i")
                        .longOpt("in-file")
                        .hasArg()
                        .argName("file")
                        .desc("input file")
                        .required()
                        .build()
        );

        options.addOption(
                Option.builder("o")
                        .longOpt("out-file")
                        .hasArg()
                        .argName("file")
                        .desc("output file")
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

            File inFile = new File(cmd.getOptionValue("i"));
            File outFile = new File(cmd.getOptionValue("o"));

            FolderEncryptor fe;
            if(cmd.hasOption("p")) {
                fe = new FolderEncryptor(cmd.getOptionValue("p"));
            } else if(cmd.hasOption("k")) {
                String encodedKey = cmd.getOptionValue("k");
                byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
                Key key = new SecretKeySpec(keyBytes, "AES");
                fe = new FolderEncryptor(key);
            } else {
                fe = new FolderEncryptor();
                byte[] keyBytes = fe.getEncryptor().getKey().getEncoded();
                String encodedKey = Base64.getEncoder().encodeToString(keyBytes);
                System.out.println("Base64 encoded key: " + encodedKey);
            }
            try {
                if(cmd.hasOption("d")) {
                    fe.decrypt(inFile, outFile);
                } else {
                    fe.encrypt(inFile, outFile);
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp(FolderEncryptor.class.getSimpleName(), options);
        }
        System.exit(0);
    }
}