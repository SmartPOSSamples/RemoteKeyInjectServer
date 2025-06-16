package com.cloudpos.rki.pinpad;

import com.cloudpos.rki.pinpad.keyinfo.DukptAesKeyInfo;
import com.cloudpos.rki.pinpad.keyinfo.DukptKeyInfo;
import com.cloudpos.rki.pinpad.keyinfo.MasterKeyInfo;
import com.cloudpos.rki.pinpad.keyinfo.TransportKeyInfo;
import com.cloudpos.rki.util.ByteConvert;
import com.cloudpos.rki.util.CertUtils;
import com.cloudpos.rki.util.CommonUtils;
import com.cloudpos.rki.util.PinPadKeyStore;

/**
 * Cipher Key Info
 * @author lizhou
 */
public class CKeyInfo {
	private static final int LEN_PUB_KEY_LEN = 4;
	private static final int LEN_PUB_KEY = 4096;
	private static final int LEN_RANDOM = 32;
	private static final int LEN_CIPHER_KEY_INFO = 256;
	private static final int LEN_SIG = 256;

	private AuthInfo authInfo;
	private PinPadKeyStore ks = PinPadKeyStore.getInstance();
	private String sn;

	private byte[] bPubKeyLen;
	private byte[] bPubKey;
	private byte[] bRandom;
	private byte[] bCipherKeyInfo;
	private byte[] bSig;

	private byte[] plainKeyInfo;
	
	private boolean aes;
	private String rid;

	public CKeyInfo(AuthInfo authInfo, String sn) {
		this.authInfo = authInfo;
		this.sn = sn;
		
		bPubKey = CertUtils.asPemBytes(ks.getCert());
		bPubKeyLen = ByteConvert.int2byte4(bPubKey.length, false);
		bRandom = authInfo.getRandom();
	}

	public byte[] build() {
		// use terminal cert to encrypt plain key
		bCipherKeyInfo = CertUtils.encrypt(authInfo.getCert(), plainKeyInfo);

		byte[] sData = new byte[bRandom.length + bCipherKeyInfo.length];
		CommonUtils.append(bRandom, sData, 0);
		CommonUtils.append(bCipherKeyInfo, sData, bRandom.length);
		bSig = ks.sig(sData);


		byte[] result = new byte[LEN_PUB_KEY_LEN + LEN_PUB_KEY + LEN_RANDOM + LEN_CIPHER_KEY_INFO + LEN_SIG];
		int len = 0;
		CommonUtils.append(bPubKeyLen, result, len);
		len += LEN_PUB_KEY_LEN;

		CommonUtils.append(bPubKey, result, len);
		len += LEN_PUB_KEY;

		CommonUtils.append(bRandom, result, len);
		len += LEN_RANDOM;

		CommonUtils.append(bCipherKeyInfo, result, len);
		len += LEN_CIPHER_KEY_INFO;

		CommonUtils.append(bSig, result, len);
		len += LEN_SIG;

		return result;
	}

	public CKeyInfo setMasterKey(int keyIndex, byte[] key) {
		MasterKeyInfo keyInfo = new MasterKeyInfo(sn, rid);
		plainKeyInfo = keyInfo.buildMasterKey(keyIndex, key);
		return this;
	}

	public CKeyInfo setTransportKey(int keyIndex, byte[] key) {
		TransportKeyInfo keyInfo = new TransportKeyInfo(sn, rid);
		plainKeyInfo = keyInfo.buildTransportKey(keyIndex, key);
		return this;
	}

	public CKeyInfo setDukptKey(int keyIndex, int reserved, byte[] ksn, int counter, byte[] key) {
		DukptKeyInfo keyInfo = new DukptKeyInfo(sn, rid);
		plainKeyInfo = keyInfo.build(keyIndex, reserved, ksn, counter, key);
		return this;
	}
	
	public CKeyInfo setDukptAesKey(int keyIndex, int keyUsage, byte[] ksn, int counter, byte[] key) {
		DukptAesKeyInfo keyInfo = new DukptAesKeyInfo(sn, rid);
		plainKeyInfo = keyInfo.build(keyIndex, keyUsage, ksn, counter, key);
		return this;
	}
	
	public CKeyInfo setRid(String rid) {
		this.rid = rid;
		return this;
	}
	
	public CKeyInfo setAes(boolean aes) {
		this.aes = aes;
		return this;
	}
	
	public boolean isAes() {
		return aes;
	}
}
