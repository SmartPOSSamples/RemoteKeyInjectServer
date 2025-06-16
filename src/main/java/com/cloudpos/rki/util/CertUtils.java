package com.cloudpos.rki.util;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertUtils {
	private static final Logger logger = LoggerFactory.getLogger(CertUtils.class);

	public static byte[] asPemBytes(X509Certificate cert) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		PemWriter writer = new PemWriter(new OutputStreamWriter(out));
		try {
			writer.writeObject(new JcaMiscPEMGenerator(cert));
			writer.close();
			return out.toByteArray();
		} catch (Exception e) {
			logger.error("Convert X509 certificate to byte array error.", e);
		}
		return null;
	}
	
	public static X509Certificate readPemCert(Reader oreader) throws Exception {
		PemReader reader = new PemReader(oreader);
		PemObject pemObject = reader.readPemObject();
		X509CertificateHolder holder = new X509CertificateHolder(pemObject.getContent());
		X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
				.getCertificate(holder);
		reader.close();
		return cert;
	}
	
	public static X509Certificate readPemCert(InputStream inputStream) throws Exception {
		return readPemCert(new InputStreamReader(inputStream));
	}
	
	public static byte[] encrypt(X509Certificate cert, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
			return cipher.doFinal(data);
		} catch (Exception e) {
			logger.error("Encrypt data error", e);
		}
		return null;
	}

	public static byte[] sig(PrivateKey priKey, byte[] data) {
		try {
			Signature signature = Signature.getInstance("SHA256WithRSA");
			signature.initSign(priKey);
			signature.update(data);
			return signature.sign();
		} catch (Exception e) {
			logger.error("Signature data error", e);
		}
		return null;
	}

	public static boolean verifySig(PublicKey pubKey, byte[] data, byte[] sig) {
		try {
			Signature signature = Signature.getInstance("SHA256WithRSA");
			signature.initVerify(pubKey);
			signature.update(data);
			return signature.verify(sig);
		} catch (Exception e) {
			logger.error("Verify signature data error", e);
		}
		return false;
	}

	public static byte[] des(byte[] key, byte[] data, int mode) {
		try {
			Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			cipher.init(mode, keyFactory.generateSecret(new DESKeySpec(key)), new SecureRandom());
			byte[] result = new byte[data.length];
			// 如果数据超过8位，循环每8位进行加解密，然后进行拼接
			int offset = 0;
			for (int i = 0; i < data.length / 8; i++) {
				// 需要处理的数据逐8位取出
				byte[] tmp = new byte[8];
				System.arraycopy(data, offset, tmp, 0, 8);
				// 进行加解密计算
				byte[] tmpResult = cipher.doFinal(tmp);
				// 放入返回结果中
				System.arraycopy(tmpResult, 0, result, offset, 8);

				offset += 8;
			}
			return result;
		} catch (Throwable e) {
			logger.error("Encrypt data by DES error", e);
		}
		return null;
	}

	public static byte[] desEncrypt(byte[] key, byte[] data) {
		return des(key, data, Cipher.ENCRYPT_MODE);
	}

	public static byte[] desDecrypt(byte[] key, byte[] data) {
		return des(key, data, Cipher.DECRYPT_MODE);
	}

	public static byte[] doubleDesEncrypt(byte[] key, byte[] data) {
		byte[] result = null;
		if (key.length != 16) {
			throw new IllegalArgumentException("Expected length of des key is 16! [" + key.length + "]");
		}
		// 拆分密钥
		byte[] keyLeft = new byte[8];
		byte[] keyRight = new byte[8];
		System.arraycopy(key, 0, keyLeft, 0, 8);
		System.arraycopy(key, 8, keyRight, 0, 8);
		// 使用Left进行加密
		byte[] tmp = desEncrypt(keyLeft, data);
		tmp = desDecrypt(keyRight, tmp);
		result = desEncrypt(keyLeft, tmp);
		return result;
	}

}
