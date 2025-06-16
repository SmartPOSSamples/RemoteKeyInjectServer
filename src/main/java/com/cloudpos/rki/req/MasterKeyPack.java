package com.cloudpos.rki.req;

import java.util.List;

import com.cloudpos.rki.pinpad.AuthInfo;
import com.cloudpos.rki.pinpad.CKeyInfo;
import com.cloudpos.rki.util.ByteConvert;
import com.cloudpos.rki.util.CertUtils;
import com.cloudpos.rki.util.CommonUtils;
import com.cloudpos.rki.util.KeyList;
import com.cloudpos.rki.util.KeyList.KeyInfo;
import com.cloudpos.rki.util.KeyList.MasterKey;

public class MasterKeyPack extends KeyPack {
	
	@Override
	public void inject() throws Exception {
		AuthInfo authInfo = getAndCheckCert();
		// Get master key from configuration file by sn.
		String sn = new String(authInfo.getSN());
		logger.debug("{} - Sn: {}", rid, sn);
		KeyInfo keyInfo = KeyList.get(sn);
		if (keyInfo == null) {
			write(new Result(Result.NO_AVAILABLE_KEY, "No available key"));
			return;
		}
		List<MasterKey> list = keyInfo.getMasterKeys();
		if (list == null || list.size() < 1) {
			write(new Result(Result.NO_AVAILABLE_KEY, "No available key"));
			return;
		}
		Result result = new Result(Result.SUCCESS, "Get key success");
		for (MasterKey masterKey : list) {
			RKey key = buildMaterKey(authInfo, sn, masterKey);
			result.addKeyData(key);
		}
		write(result);
	}
	
	private RKey buildMaterKey(AuthInfo authInfo, String sn, MasterKey masterKey) throws Exception {
		// Get master key from keylist.txt file
		int keyIndex = masterKey.getKeyIndex();
		byte[] key = masterKey.getKey();

		ctx.channel().attr(MASTER_KEY_INFO).set(KeyList.get(sn));

		logger.debug("{} - Prepare to build master key info...", rid);
		CKeyInfo cKeyInfo = new CKeyInfo(authInfo, sn).setRid(rid);
		byte[] data = cKeyInfo.setMasterKey(keyIndex, key).build();

		return new RKey().setAes(false).setKeyData(data);
	}
	
	@Override
	public void validate() throws Exception {
		KeyInfo keyInfo = ctx.channel().attr(MASTER_KEY_INFO).get();
		List<MasterKey> list = keyInfo.getMasterKeys();
		if (list == null || list.size() < 1) {
			write(new Result(Result.NO_AVAILABLE_KEY, "No available key"));
			return;
		}
		Result result = new Result(Result.SUCCESS, "Validate key success");
		for (MasterKey masterKey : list) {
			RKey key = downloadingValidationMasterKeyInfo(masterKey);
			result.addKeyData(key);
		}
		write(result);
	}
	
	private RKey downloadingValidationMasterKeyInfo(MasterKey masterKey) throws Exception {
		logger.debug("{} - Key index: {}, content: {}", rid, masterKey.getKeyIndex(), CommonUtils.toHex(masterKey.getKey()));

		byte[] masterKeyId = new byte[] { (byte) masterKey.getKeyIndex() };
		byte[] userKeyId = new byte[] { 0x02 };
		byte[] userKeyType = new byte[] { 0x02 };

		byte[] plainUserKey = CommonUtils.randomString(16).getBytes();
		logger.debug("{} - Plain User Key: {}", rid, CommonUtils.toHex(plainUserKey));
		byte[] encryptUserKey = CertUtils.doubleDesEncrypt(masterKey.getKey(), plainUserKey);
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

		byte[] result = CommonUtils.append(masterKeyId, userKeyId, userKeyType,
				userKeyLen, userKey,
				checkValueLen, checkValue,
				msgDataLen, msgData,
				cipherDataLen, cipherData);
		
		return new RKey().setAes(false).setKeyData(result);
	}
	
}
