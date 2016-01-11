package com.crowley.encryption;


import java.io.File;

import org.junit.Assert;
import org.junit.Test;

public class MD5UtilsTest {

	@Test
	public void testMD5UsingString() {
		//Do not fit the Chinese words because of the character encoding.
		//Assert.assertEquals("...", MD5Utils.getMD5("舒满昌"));
		//Assert.assertEquals("...", MD5Utils.getMD5("你会说中文吗？"));
		Assert.assertEquals("39D66ACE4186B62C0FDAE57161D44669", MD5Utils.getMD5("Crowley"));
		Assert.assertEquals("FD994A92D8EB704817268D5980911C1B", MD5Utils.getMD5("Who are you ?"));
		Assert.assertEquals("0449EAE4BB72AC9620A8842039FF9C6C", MD5Utils.getMD5("Could you speak mandarin?"));
		Assert.assertEquals("47E70D30393989D6455C6429B88FA407", MD5Utils.getMD5("36564135143541541354152"));
	}
	
	@Test
	public void testMD5UsingFile() {
		Assert.assertEquals("9f496da626e553208aad5950ba5fbd01".toUpperCase(), MD5Utils.getMD5(new File("D:\\Documents\\Downloads\\apache-tomcat-8.0.30.zip")));
	}
	
}
