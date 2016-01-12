package com.crowley.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class is used for generating SHA algorithm, including SHA-1, SHA-256, SHA-384 and SHA-512.
 * @author Crowly shumanchang826@gmail.com
 */
public class SHAUtils {
	public static final String SHA_1 = "SHA-1";
	public static final String SHA_256 = "SHA-256";
	public static final String SHA_384 = "SHA-384";
	public static final String SHA_512 = "SHA-512";

	/**
	 * Get the message digest with specified SHA algorithm.
	 * @param algorithm Support these algorithm: SHA-1, SHA-256, SHA-384 and SHA-512.
	 * @param source The String to be hashed.
	 * @return The hashed String based on SHA.
	 */
	public static String getSHA(String algorithm, String source) {
		String encoded = null;
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			md.update(source.getBytes());
			byte[] digest = md.digest();
			encoded = bytes2String(digest);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return encoded;
	}
	
	/**
	 * Get the message digest with SHA-1 algorithm.
	 * @param source The String to be hashed.
	 * @return The hashed String based on SHA.
	 */
	public static String getSHA(String source) {
		return getSHA(SHA_1, source);
	}
	
	/**
	 * Get the file digest with specified SHA algorithm.
	 * @param algorithm Support these algorithm: SHA-1, SHA-256, SHA-384 and SHA-512.
	 * @param file The file to be calculated SHA digest.
	 * @return SHA digest String of the File.
	 */
	public static String getSHA(String algorithm, File file) {
		String sha = null;
		FileInputStream in = null;
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			in = new FileInputStream(file);
			byte[] buffer = new byte[1024];
			int len = -1;
			while((len = in.read(buffer)) != -1) {
				md.update(buffer, 0, len);
			}
			byte[] digest = md.digest();
			sha = bytes2String(digest);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} finally {
			if(in != null) {
				try {
					in.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		
		return sha;
	}
	
	/**
	 * Get the file digest with SHA-1 algorithm.
	 * @param file The file to be calculated SHA digest.
	 * @return SHA digest String of the File.
	 */
	public static String getSHA(File file) {
		return getSHA(SHA_1, file);
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
	
}
