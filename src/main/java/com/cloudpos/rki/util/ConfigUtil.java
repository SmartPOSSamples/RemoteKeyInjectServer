package com.cloudpos.rki.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ConfigUtil {
	private static final Logger logger = LoggerFactory.getLogger(ConfigUtil.class);
	private static Properties properties = new Properties();

	static {
		try {
			File file = new File("config.properties");
			logger.info("load config file:" + file.getAbsolutePath());
			properties.load(new FileInputStream(file));
		} catch (FileNotFoundException e) {
			logger.error("", e);
		} catch (IOException e) {
			logger.error("", e);
		}
	}

	public static String getProperty(String key) {
		return properties.getProperty(key);
	}

	public static int getLocalPort() {
		return Integer.parseInt(properties.getProperty("localPort"));
	}

	public static String getKeyStorePath() {
		return properties.getProperty("keystore.path");
	}

	public static String getKeyStorePass() {
		return properties.getProperty("keystore.pass");
	}

	public static String getTrustStorePath() {
		return properties.getProperty("truststore.path");
	}

	public static String getTrustStorePass() {
		return properties.getProperty("truststore.pass");
	}

	public static String getPinPadKeyStore() {
		return properties.getProperty("pinpad.keystore");
	}

	public static char[] getPinPadKeyStorePasswd() {
		return properties.getProperty("pinpad.keystore.passwd").toCharArray();
	}

	public static String getPinPadKeyAlias() {
		return properties.getProperty("pinpad.key.alias");
	}

	public static char[] getPinPadKeyPasswd() {
		return properties.getProperty("pinpad.key.passwd").toCharArray();
	}
	
	public static String getPinpadRootCert() {
		return properties.getProperty("pinpad.root.cert");
	}
	
	public static boolean contain(String model) {
		return properties.containsKey("key.len." + model.toLowerCase());
	}
	
	public static int getKeyLen(String model) {
		return Integer.parseInt(properties.getProperty("key.len." + model.toLowerCase()));
	}
}
