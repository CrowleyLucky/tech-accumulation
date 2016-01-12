package com.crowley.encryption;

import org.junit.Test;

import com.crowley.encryption.RSAUtils.RSAKeyPair;

public class RSAUtilsTest {

	@Test
	public void testGenerateRSAPair() {
		RSAKeyPair keyPair = RSAUtils.generateRSAPair();
		System.out.println("public key:" + keyPair.getPublicKey());
		System.out.println("private key:" + keyPair.getPrivateKey());
	}
	
	
	@Test
	public void testEncryptAndDecryptWithDefaultInitKeySize() {
		String msg = "I am Crowley£¡ Testing default initial key size.";
		RSAKeyPair keyPair = RSAUtils.generateRSAPair();
		System.out.println("public key:" + keyPair.getPublicKey());
		System.out.println("private key:" + keyPair.getPrivateKey());
		String encodedMsg = RSAUtils.encodeMessage(keyPair.getPublicKey(), msg);
		String decodedMsg = RSAUtils.decodeMessage(keyPair.getPrivateKey(), encodedMsg);
		System.out.println("Message:" + msg);
		System.out.println("Encoded message:" + encodedMsg);
		System.out.println("Decoded message:" + decodedMsg);
	}
	
	@Test
	public void testEncryptAndDecryptWithKeySize512() {
		String msg = "I am Crowley£¡ Testing initial key size of 512.";
		RSAKeyPair keyPair = RSAUtils.generateRSAPair(RSAUtils.KEY_SIZE_512);
		System.out.println("public key:" + keyPair.getPublicKey());
		System.out.println("private key:" + keyPair.getPrivateKey());
		String encodedMsg = RSAUtils.encodeMessage(keyPair.getPublicKey(), msg);
		String decodedMsg = RSAUtils.decodeMessage(keyPair.getPrivateKey(), encodedMsg);
		System.out.println("Message:" + msg);
		System.out.println("Encoded message:" + encodedMsg);
		System.out.println("Decoded message:" + decodedMsg);
	}
	
	@Test
	public void testEncryptAndDecryptWithKeySize1024() {
		String msg = "I am Crowley£¡ Testing initial key size of 1024.";
		RSAKeyPair keyPair = RSAUtils.generateRSAPair(RSAUtils.KEY_SIZE_1024);
		System.out.println("public key:" + keyPair.getPublicKey());
		System.out.println("private key:" + keyPair.getPrivateKey());
		String encodedMsg = RSAUtils.encodeMessage(keyPair.getPublicKey(), msg);
		String decodedMsg = RSAUtils.decodeMessage(keyPair.getPrivateKey(), encodedMsg);
		System.out.println("Message:" + msg);
		System.out.println("Encoded message:" + encodedMsg);
		System.out.println("Decoded message:" + decodedMsg);
	}
	
	@Test
	public void testEncryptAndDecryptWithKeySize2048() {
		String msg = "I am Crowley£¡ Testing initial key size of 2048.";
		RSAKeyPair keyPair = RSAUtils.generateRSAPair(RSAUtils.KEY_SIZE_2048);
		System.out.println("public key:" + keyPair.getPublicKey());
		System.out.println("private key:" + keyPair.getPrivateKey());
		String encodedMsg = RSAUtils.encodeMessage(keyPair.getPublicKey(), msg);
		String decodedMsg = RSAUtils.decodeMessage(keyPair.getPrivateKey(), encodedMsg);
		System.out.println("Message:" + msg);
		System.out.println("Encoded message:" + encodedMsg);
		System.out.println("Decoded message:" + decodedMsg);
	}
	
}
