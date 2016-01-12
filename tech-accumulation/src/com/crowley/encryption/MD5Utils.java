package com.crowley.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *  This class is used for generating MD5 digest.
 * @author Crowly shumanchang826@gmail.com
 */
public class MD5Utils {
	private static final String algorithm = "MD5";
	
	/** Generate MD5 digest of String Object.
	 * @param source The source String to be calculated md5 digest.
	 * @return The md5 digest.
	 */
	public static String getMD5(String source) {
		String md5 = null;
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			md.update(source.getBytes());
			byte[] digest = md.digest();
			md5 = bytes2String(digest);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return md5;
	}
	
	/**
	 * Generate MD5 digest of a file.
	 * @param file The file to be calculated md5 digest.
	 * @return The md5 digest.
	 */
	public static String getMD5(File file) {
		String md5 = null;
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
			md5 = bytes2String(digest);
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
		
		return md5;
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
