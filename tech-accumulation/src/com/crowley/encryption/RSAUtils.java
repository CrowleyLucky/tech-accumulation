package com.crowley.encryption;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/** This class is used for generating RSA public key and private key pair, and encrypting, decrypting String based on RSA algorithm. 
 * @author Crowly shumanchang826@gmail.com
 */
public class RSAUtils {
	private static final String algorithm = "RSA";
	public static final int KEY_SIZE_512 = 512;
	public static final int KEY_SIZE_1024 = 1024;
	public static final int KEY_SIZE_2048 = 2048;
	
	/**
	 * Generate a pair of public key and private key based on RSA algorithm with an initial key size.
	 * @param initKeySize initial key size.
	 * @return RSAKeyPair, including public key String and private key String.
	 */
	public static RSAKeyPair generateRSAPair(int initKeySize) {
		if(initKeySize < 0) {
			throw new RuntimeException("The param initKeySize should be a positive number.");
		}
		String publicKeyStr = null;
		String privateKeyStr = null;
		boolean success = true;
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
			generator.initialize(initKeySize);
			KeyPair keyPair = generator.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			publicKeyStr = bytes2String(publicKey.getEncoded());
			privateKeyStr = bytes2String(privateKey.getEncoded());
		} catch (NoSuchAlgorithmException e) {
			success = false;
			e.printStackTrace();
		}
		
		return success ? new RSAKeyPair(publicKeyStr, privateKeyStr) : null;
	}
	
	/**
	 * Generate a pair of public key and private key based on RSA algorithm with an initial key size 1024.
	 * @return
	 */
	public static RSAKeyPair generateRSAPair() {
		return generateRSAPair(KEY_SIZE_1024);
	}
	
	/**
	 * Encrypt plain text using public key.
	 * @param publicKeyStr Public key with String format.
	 * @param message The plain text message to be encrypted.
	 * @return The encrypted message.
	 */
	public static String encodeMessage(String publicKeyStr, String message) {
		if(publicKeyStr == null || publicKeyStr.equals("")) {
			throw new RuntimeException("The param publicKeyStr should not be a null or empty value.");
		}
		if(message == null || message.equals("")) {
			throw new RuntimeException("The param message should not be a null or empty value.");
		}
		String encodedMessage = null;
		try {
			KeyFactory factory = KeyFactory.getInstance(algorithm);
			//Encode format is X.509
			X509EncodedKeySpec spec = new X509EncodedKeySpec(string2Bytes(publicKeyStr));
			PublicKey publicKey = factory.generatePublic(spec);
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] msgBytes = cipher.doFinal(message.getBytes());
			encodedMessage = bytes2String(msgBytes);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		return encodedMessage;
	}
	
	/**
	 * Decrypt plain text using private key.
	 * @param privateKeyStr Private key with String format.
	 * @param encodedMessage The plain text message to be decrypted.
	 * @return The decrypted message.
	 */
	public static String decodeMessage(String privateKeyStr, String encodedMessage) {
		if(privateKeyStr == null || privateKeyStr.equals("")) {
			throw new RuntimeException("The param privateKeyStr should not be a null or empty value.");
		}
		if(encodedMessage == null || encodedMessage.equals("")) {
			throw new RuntimeException("The param message should not be a null or empty value.");
		}
		String decodedMessage = null;
		try {
			KeyFactory factory = KeyFactory.getInstance(algorithm);
			//Decode format is PKCS#8
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(string2Bytes(privateKeyStr));
			PrivateKey privateKey = factory.generatePrivate(spec);
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] msgBytes = cipher.doFinal(string2Bytes(encodedMessage));
			decodedMessage = new String(msgBytes);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		return decodedMessage;
	}
	
	private static String bytes2String(byte[] bytes) {
		if(bytes.length <= 0) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		for(byte b : bytes) {
			sb.append(Integer.toHexString((b & 0xFF) + 0x100).substring(1).toUpperCase());
		}
		return sb.toString();
	}
	
	private static byte[] string2Bytes(String input) {
		if(input.length() <= 0 || input.length() % 2 !=0) {
			return null;
		}
		byte[] bytes = new byte[input.length() / 2];
		for(int i = 0; i < input.length(); i += 2) {
			String str = input.substring(i, i + 2);
			if(i == 0) {
				bytes[0] = (byte) Integer.parseInt(str, 16);
			} else {
				bytes[i/2] = (byte) Integer.parseInt(str, 16);
			}
		}
		return bytes;
	}
	
	public static class RSAKeyPair {
		private String publicKey;
		private String privateKey;
		
		public RSAKeyPair(String publicKey, String privateKey) {
			this.publicKey = publicKey;
			this.privateKey = privateKey;
		}
		
		public String getPublicKey() {
			return publicKey;
		}
		
		public String getPrivateKey() {
			return privateKey;
		}
		
	}
	
}
