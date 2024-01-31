package com.cloudpos.rki.util;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class PinPadKeyStore {
	private KeyStore keyStore = null;
	private X509Certificate cert = null;
	private PrivateKey priKey = null;

	private static final PinPadKeyStore ks = new PinPadKeyStore();
	public static PinPadKeyStore getInstance() {
		return ks;
	}
	private PinPadKeyStore() {
	}

	public void load(String ksPath, char[] ksPasswd, String keyAlias, char[] keyPasswd) throws Exception {
		if (ksPath.endsWith(".jks")) {
			keyStore = KeyStore.getInstance("JKS");
		} else if (ksPath.endsWith(".p12")) {
			keyStore = KeyStore.getInstance("PKCS12");
		}
		keyStore.load(new FileInputStream(new File(ksPath)), ksPasswd);

		cert = (X509Certificate) keyStore.getCertificate(keyAlias);
        priKey = (PrivateKey) keyStore.getKey(keyAlias, keyPasswd);
	}

	public byte[] sig(byte[] data) {
		return CertUtils.sig(priKey, data);
	}

	public X509Certificate getCert() {
		return this.cert;
	}

}
