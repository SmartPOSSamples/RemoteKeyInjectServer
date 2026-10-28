package com.cloudpos.rki.pinpad;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.cloudpos.rki.util.ByteConvert;
import com.cloudpos.rki.util.CertUtils;
import com.cloudpos.rki.util.CommonUtils;

/**
 * The authenticate information from PINPad HSM module. It's unique for every key injecting transaction.
 */
public class AuthInfo {

    public static final int LEN_PUB_KEY_LEN = 4;
	    public static final int LEN_PUB_KEY = 4096;
	    public static final int LEN_RANDOM = 32;
	    public static final int LEN_SN_LEN = 1;
	    public static final int LEN_SN = 31;
	    public static final int LEN_SIG = 256;
	    public static final int LEN_SIG_4096 = 512;

	    public static final int MSG_SIZE = LEN_PUB_KEY_LEN + LEN_PUB_KEY + LEN_RANDOM + LEN_SN_LEN + LEN_SN + LEN_SIG;
	    public static final int MSG_SIZE_4096 = LEN_PUB_KEY_LEN + LEN_PUB_KEY + LEN_RANDOM + LEN_SN_LEN + LEN_SN + LEN_SIG_4096;

	    private byte[] msg = new byte[MSG_SIZE];
	    private byte[] bPubKeyLen;
	    private byte[] bPubKey; // pem format
	    private byte[] bRandom;
	    private byte[] bSnLen;
	    private byte[] bSn;
	    private byte[] bSig;

	    private X509Certificate cert;
	    private byte[] realSn;

	    public AuthInfo(byte[] msg) {
	    	this.msg = msg;

	    	parseMsg();
	    	parseSN();
	    	parseCert();
	        verifyMsg();
	    }

	    private void parseMsg() {
	    	if (msg.length != MSG_SIZE && msg.length != MSG_SIZE_4096) {
	    		throw new IllegalArgumentException("Unsupported message length: " + msg.length
	    				+ " (expected " + MSG_SIZE + " or " + MSG_SIZE_4096 + ")");
	    	}

	    	int len = 0;
	        bPubKeyLen = CommonUtils.subBytes(msg, len, LEN_PUB_KEY_LEN);
	        len += LEN_PUB_KEY_LEN;

	        bPubKey = CommonUtils.subBytes(msg, len, LEN_PUB_KEY);
	        len += LEN_PUB_KEY;

	        bRandom = CommonUtils.subBytes(msg, len, LEN_RANDOM);
	        len += LEN_RANDOM;

	        bSnLen = CommonUtils.subBytes(msg, len, LEN_SN_LEN);
	        len += LEN_SN_LEN;

	        bSn = CommonUtils.subBytes(msg, len, LEN_SN);
	        len += LEN_SN;

	        // Signature length is the remaining bytes of the message:
	        // 256 bytes for RSA-2048 signature, 512 bytes for RSA-4096 signature.
	        int sigLen = msg.length - len;
	        if (sigLen != LEN_SIG && sigLen != LEN_SIG_4096) {
	        	throw new IllegalArgumentException("Unsupported signature length: " + sigLen
	        			+ " (expected " + LEN_SIG + " or " + LEN_SIG_4096 + ")");
	        }
	        bSig = CommonUtils.subBytes(msg, len, sigLen);
	        len += sigLen;
	    }

	    private void parseSN() {
	    	realSn = Arrays.copyOf(bSn, bSnLen[0]);
	    }

	    private void parseCert() {
	    	byte[] certBytes = CommonUtils.subBytes(bPubKey, 0, ByteConvert.byte2int4(bPubKeyLen, false));
	    	PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(certBytes)));
	        try {
	    		PemObject pemObject = pemReader.readPemObject();
	    		X509CertificateHolder holder = new X509CertificateHolder(pemObject.getContent());
	    		cert = new JcaX509CertificateConverter().getCertificate(holder);
	            // verify the cert validity
	            cert.checkValidity(new Date());
	        } catch (Exception e) {
	        	throw new IllegalArgumentException("Extract certificate from message error", e);
	        } finally {
	        	try {
					pemReader.close();
				} catch (IOException e) {
				}
	        }
	    }

	    private void verifyMsg() {
	        int snLength = getSN().length;
	        byte[] data = new byte[snLength + bRandom.length];
	        CommonUtils.append(getSN(), data, 0);
	        CommonUtils.append(bRandom, data, snLength);
	        System.out.println("bSig.length:"+bSig.length);
	        boolean r = CertUtils.verifySig(cert.getPublicKey(), data, bSig);
	        if (!r) {
	        	throw new IllegalArgumentException("Verify message signature error");
	        }
	    }

	    public X509Certificate getCert() {
	        return cert;
	    }

	    /**
	     * Get the PubKeyP in simple certificate in PEM format.
	     * The certificate is issued by POS Root Public Key.
	     *
	     * @return
	     */
	    public byte[] getPubKeyPEMBuffer() {
	        return bPubKey;
	    }

	    /**
	     * Get the random number of this key injecting transaction.
	     *
	     * @return
	     */
	    public byte[] getRandom() {
	        return bRandom;
	    }

	    /**
	     * Get the serial number of POS.
	     *
	     * @return
	     */
	    public byte[] getSN() {
	        return realSn;
	    }


	    /**
	     * Get the signature of the SN and the Random number.
	     *
	     * @return
	     */
	    public byte[] getSignature() {
	        return bSig;
	    }
}
