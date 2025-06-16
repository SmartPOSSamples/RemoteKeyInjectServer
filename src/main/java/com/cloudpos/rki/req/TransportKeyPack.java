package com.cloudpos.rki.req;

import java.util.List;

import com.cloudpos.rki.pinpad.AuthInfo;
import com.cloudpos.rki.pinpad.CKeyInfo;
import com.cloudpos.rki.util.ByteConvert;
import com.cloudpos.rki.util.CertUtils;
import com.cloudpos.rki.util.CommonUtils;
import com.cloudpos.rki.util.KeyList;
import com.cloudpos.rki.util.KeyList.KeyInfo;
import com.cloudpos.rki.util.KeyList.TransportKey;

public class TransportKeyPack extends KeyPack {
	
	@Override
	public void inject() throws Exception {
		AuthInfo authInfo = getAndCheckCert();
		// Get transport key from configuration file by sn.
		String sn = new String(authInfo.getSN());
		logger.debug("{} - Sn: {}", rid, sn);
		KeyInfo keyInfo = KeyList.get(sn);
		if (keyInfo == null) {
			write(new Result(Result.NO_AVAILABLE_KEY, "No available key"));
//			write(ByteConvert.int2byte2(0));
			return;
		}
		List<TransportKey> list = keyInfo.getTransportKeys();
		if (list == null || list.size() < 1) {
			write(new Result(Result.NO_AVAILABLE_KEY, "No available key"));
//			write(ByteConvert.int2byte2(0));
			return;
		}
		Result result = new Result(Result.SUCCESS, "Get key success");
		for (TransportKey transportKey : list) {
			RKey key = buildTransportKey(authInfo, sn, transportKey);
			result.addKeyData(key);
		}
		write(result);
	}
	
	private RKey buildTransportKey(AuthInfo authInfo, String sn, TransportKey transportKey) throws Exception {
		// Get transport key from keylist.txt file
		int keyIndex = transportKey.getKeyIndex();
		byte[] key = transportKey.getKey();

		ctx.channel().attr(TRANSPORT_KEY_INFO).set(KeyList.get(sn));

		logger.debug("{} - Prepare to build transport key info...", rid);
		CKeyInfo cKeyInfo = new CKeyInfo(authInfo, sn);
		byte[] data = cKeyInfo.setTransportKey(keyIndex, key).build();

		return new RKey().setAes(false).setKeyData(data);
	}
	
	@Override
	public void validate() throws Exception {
		KeyInfo keyInfo = ctx.channel().attr(TRANSPORT_KEY_INFO).get();
		List<TransportKey> list = keyInfo.getTransportKeys();
		if (list == null || list.size() < 1) {
			write(new Result(Result.NO_AVAILABLE_KEY, "No available key"));
			return;
		}
		Result result = new Result(Result.SUCCESS, "Validate key success");
		for (TransportKey transportKey : list) {
			RKey key = downloadingValidationTransportKeyInfo(transportKey);
			result.addKeyData(key);
		}
		write(result);
	}
	
	private RKey downloadingValidationTransportKeyInfo(TransportKey transportKey) throws Exception {
		logger.debug("{} - Key index: {}, content: {}", rid, transportKey.getKeyIndex(), CommonUtils.toHex(transportKey.getKey()));

		byte[] transportKeyId = new byte[] { (byte) transportKey.getKeyIndex() };
		byte[] userKeyId = new byte[] { 0x02 };
		byte[] userKeyType = new byte[] { 0x02 };

		byte[] plainUserKey = CommonUtils.randomString(16).getBytes();
		logger.debug("{} - Plain User Key: {}", rid, CommonUtils.toHex(plainUserKey));
		byte[] encryptUserKey = CertUtils.doubleDesEncrypt(transportKey.getKey(), plainUserKey);
		logger.debug("{} - Encrypt User Key: {}", rid, CommonUtils.toHex(encryptUserKey));

		byte[] checkValue = CommonUtils.subBytes(CertUtils.doubleDesEncrypt(plainUserKey,
				new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}), 0, 8);
		logger.debug("{} - Check Value: {}", rid, CommonUtils.toHex(checkValue));
		byte[] checkValueLen = ByteConvert.int2byte2(checkValue.length);

		byte[] userKey = encryptUserKey;
		logger.debug("{} - User Key: {}", rid, CommonUtils.toHex(userKey));
		byte[] userKeyLen = ByteConvert.int2byte2(userKey.length);

		byte[] msgData = CommonUtils.randomString(16).getBytes();
		logger.debug("{} - Msg Data: {}", rid, CommonUtils.toHex(msgData));
		byte[] msgDataLen = ByteConvert.int2byte2( msgData.length);

		byte[] cipherData = CertUtils.doubleDesEncrypt(plainUserKey, msgData);
		logger.debug("{} - Cipher Data: {}", rid, CommonUtils.toHex(cipherData));
		byte[] cipherDataLen = ByteConvert.int2byte2(cipherData.length);

		byte[] result = CommonUtils.append(transportKeyId, userKeyId, userKeyType,
				userKeyLen, userKey,
				checkValueLen, checkValue,
				msgDataLen, msgData,
				cipherDataLen, cipherData);
		
		return new RKey().setAes(false).setKeyData(result);
	}
	
}
