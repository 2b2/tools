package de.ef.cryptout;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// a small pipelined commandline program to encrypt and decrypt
// the output of another program (like echo)
// 
// in encrypt mode (--encrypt) it creates a AES-128/AES-256 session key
// and prepends this key encrypted with the given RSA public key to the
// encrypted output of the input program
// 
// in decrypt mode (--decrypt) it firstly decrypts the AES session key
// with the RSA private key (the AES key size is automatically detected)
// then decrypts the output of the input program
// 
// in both modes everything (except the parameters like the RSA key
// location of course) is written to System.out and read from System.in
//
// see README for use examples
// 
// version: 1.1, date: 10.07.2016, author: Erik Fritzsche
// TODO add validation in form of signature or hash or something like this
public class Cryptout{
	
	private final static String VERSION = "Version 1.1 Build 20160710002";
	private final static int DEFAULT_BUFFER_SIZE = 8_388_608, // 8 MB
							 BLOCK_SIZE = 16; // byte
	
	
	public static void main(String ... args){
		if(args.length < 1){
			System.err.println("The RSA key file has to be specified.");
			System.exit(1);
		}
		switch(args[args.length - 1]){
			case "--version" : System.out.println(VERSION); System.exit(0);
			case "--help"    : printHelp()                ; System.exit(0);
		}
		// extract all flags from args
		String[] flags = Arrays.copyOfRange(args, 0, args.length - 1);
		
		// TODO may add alias flags (like "-e" for "--encrypt")
		// possible flags
		boolean encryptStream = false, base64EncodedKey = false, verbose = false, useAes256 = false;
		// loop thru given flags
		for(String flag : flags){
			switch(flag){
				case "--encrypt" : encryptStream = true                       ; break;
				case "--decrypt" : encryptStream = false                      ; break;
				case "--base64"  : base64EncodedKey = true                    ; break;
				case "--aes256"  : useAes256 = true                           ; break;
				case "--verbose" : verbose = true                             ; break;
				default          : System.err.println("Unknown flag: " + flag); break;
			}
		}
		
		// setup keys and initialization vector (IV) for AES/CBC
		SecretKey sessionKey = null;
		IvParameterSpec sessionIv = null;
		String rsaKeyFile = args[args.length - 1];
		try(InputStream rsaKeyStream = getRSAKeyStream(rsaKeyFile, base64EncodedKey)){
			
			// load RSA key (encrypt -> public / decrypt -> private)
			ByteArrayOutputStream rsaKeyBytes = new ByteArrayOutputStream(2048);
			copy(rsaKeyStream, rsaKeyBytes, 2048);
			
			byte[] rsaKeyData = rsaKeyBytes.toByteArray();
			
			byte[] sessionIvBytes;
			if(encryptStream == true){
				// create RSA public key
				X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(rsaKeyData);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PublicKey rsaPubicKey = keyFactory.generatePublic(publicKeySpec);

				// generate AES key for current session
				KeyGenerator sessionKeyGenerator = KeyGenerator.getInstance("AES");
				sessionKeyGenerator.init(useAes256 == true ? 256 : 128);
				sessionKey = sessionKeyGenerator.generateKey();
				
				// create encrypted AES session key
				Cipher sessionKeyCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				sessionKeyCipher.init(Cipher.ENCRYPT_MODE, rsaPubicKey);
				byte[] encryptedSessionKey = sessionKeyCipher.doFinal(sessionKey.getEncoded());
				
				// write encrypted AES session key length (as 4 byte integer) and data to output
				System.out.write(ByteBuffer.allocate(4).putInt(encryptedSessionKey.length).array());
				System.out.write(encryptedSessionKey);
				
				// TODO may also encrypt IV (if this is even necessary)
				// create secure random IV
				sessionIvBytes = new byte[BLOCK_SIZE];
				SecureRandom sessionIvRandom = new SecureRandom();
				sessionIvRandom.nextBytes(sessionIvBytes);
				
				// write IV bytes to output
				System.out.write(sessionIvBytes);
			}
			else{
				// TODO load encrypted RSA private key
				// create RSA private key
				PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(rsaKeyData);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PrivateKey rsaPrivateKey = keyFactory.generatePrivate(privateKeySpec);
				
				// read encrypted AES session key length (as 4 byte integer)
				byte[] rawEncryptedSessionKeyLength = new byte[4];
				System.in.read(rawEncryptedSessionKeyLength);
				int encryptedSessionKeyLength = ByteBuffer.wrap(rawEncryptedSessionKeyLength).getInt();
				
				// read encrypted AES session key
				byte[] encryptedSessionKey = new byte[encryptedSessionKeyLength];
				System.in.read(encryptedSessionKey);
				
				// decrypt AES session key
				Cipher sessionKeyCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				sessionKeyCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
				byte[] decryptedSessionKey = sessionKeyCipher.doFinal(encryptedSessionKey);
				
				// set AES session key
				sessionKey = new SecretKeySpec(decryptedSessionKey, "AES");
				
				// read and set session IV bytes
				sessionIvBytes = new byte[BLOCK_SIZE];
				System.in.read(sessionIvBytes);
			}
			
			// set session IV
			sessionIv = new IvParameterSpec(sessionIvBytes);
			
		}catch(FileNotFoundException e){
			System.err.println("RSA key file \"" + rsaKeyFile + "\" not found!");
			System.exit(2);
		}catch(Throwable t){
			System.err.println("Error while setting keys (use option \"--verbose\" for more details)");
			if(verbose == true){
				t.printStackTrace(System.err);
			}
			System.exit(1);
		}
		
		// copy and encrypt/decrypt System.in -> System.out
		try{
			// init session cipher stream
			Cipher sessionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			if(encryptStream == true){
				sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey, sessionIv);
			}
			else{
				sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey, sessionIv);
			}
			OutputStream sessionOutput = new CipherOutputStream(System.out, sessionCipher);
			
			// TODO make buffer size controllable by parameter
			// copy in to out
			copy(System.in, sessionOutput, DEFAULT_BUFFER_SIZE);
			
			sessionOutput.close();
			
		}catch(Throwable t){
			System.err.println("Error while executing program (use option \"--verbose\" for more details)");
			if(verbose == true){
				t.printStackTrace(System.err);
			}
			System.exit(1);
		}
		System.exit(0);
	}
	
	
	// gets the given file as a stream and adds base64 decoder if necessary
	private static InputStream getRSAKeyStream(String rsaKeyFile, boolean base64) throws FileNotFoundException{
		if(base64 == true){
			// TODO add support for different base64 schemas
			return Base64.getDecoder().wrap(new FileInputStream(new File(rsaKeyFile)));
		}
		return new FileInputStream(new File(rsaKeyFile));
	}
	
	
	// copies in to out until EOF is reached
	private static void copy(InputStream in, OutputStream out, int bufferSize) throws IOException{
		int read;
		byte[] buffer = new byte[bufferSize];
		
		while((read = in.read(buffer, 0, buffer.length)) != -1){
			out.write(buffer, 0, read);
		}
		
		out.flush();
	}
	
	
	// TODO print the help page
	private static void printHelp(){
		System.out.println("TODO");
	}
}