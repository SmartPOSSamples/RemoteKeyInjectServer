package com.cloudpos.rki.server;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cloudpos.rki.pinpad.AuthInfo;
import com.cloudpos.rki.pinpad.CKeyInfo;
import com.cloudpos.rki.util.ByteConvert;
import com.cloudpos.rki.util.CertUtils;
import com.cloudpos.rki.util.CommonUtils;
import com.cloudpos.rki.util.KeyList;
import com.cloudpos.rki.util.KeyList.DukptKey;
import com.cloudpos.rki.util.KeyList.KeyInfo;
import com.cloudpos.rki.util.KeyList.MasterKey;
import com.cloudpos.rki.util.KeyList.TransportKey;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.AttributeKey;

public class MessagePack implements Runnable {
	private static final Logger logger = LoggerFactory.getLogger(MessagePack.class);
	private static final AttributeKey<KeyInfo> MASTER_KEY_INFO = AttributeKey.<KeyInfo>valueOf("MASTER_KEY_INFO");
	private static final AttributeKey<KeyInfo> TRANSPORT_KEY_INFO = AttributeKey.<KeyInfo>valueOf("TRANSPORT_KEY_INFO");

	private ChannelHandlerContext ctx;
	private byte[] inData;

	public MessagePack(byte[] inData, ChannelHandlerContext ctx) {
		this.inData = inData;
		this.ctx = ctx;
	}

	private void write(byte[] data) throws InterruptedException {
		logger.debug("Return data length: " + data.length);
		logger.debug("Return data: " + CommonUtils.toHex(data));

		ByteBuf byteBuf = ctx.alloc().buffer();
		byteBuf.writeBytes(CommonUtils.intTo2Bytes(data.length));
		byteBuf.writeBytes(data);
		ctx.writeAndFlush(byteBuf).sync();
	}

	@Override
	public void run() {
		try {
			logger.debug("Send remote server buffer: " + CommonUtils.toHex(inData));
			byte reqType = inData[0];
			if (reqType == 0x01) { // Request to inject master key
				buildMaterKey();

			} else if (reqType == 0x02) { // Request to validate master key
				downloadingValidationMasterKeyInfo();

			} else if (reqType == 0x03) {
				buildTransportKey();
				
			} else if (reqType == 0x04) { // Request to validate transport key
				downloadingValidationTransportKeyInfo();

			} else if (reqType == 0x05) { // Request to inject dukpt key
				buildDukptKey();

			}
		} catch (Exception e) {
			logger.error("", e);
		}
	}
	
	private void buildMaterKey() throws Exception {
		AuthInfo authInfo = new AuthInfo(CommonUtils.subBytes(inData, 1));
		// Get master key from configuration file by sn.
		String sn = new String(authInfo.getSN());
		logger.debug("Sn: " + sn);
		KeyInfo keyInfo = KeyList.get(sn);
		if (keyInfo == null) {
			write(ByteConvert.int2byte2(0));
			return;
		}
		List<MasterKey> list = keyInfo.getMasterKeys();
		if (list == null || list.size() < 1) {
			write(ByteConvert.int2byte2(0));
			return;
		}
		write(ByteConvert.int2byte2(list.size()));
		for (MasterKey masterKey : list) {
			buildMaterKey(authInfo, sn, masterKey);
		}
	}

	private void buildMaterKey(AuthInfo authInfo, String sn, MasterKey masterKey) throws Exception {
		logger.debug("Sn: " + sn);
		// Get master key from keylist.txt file
		int keyIndex = masterKey.getKeyIndex();
		byte[] key = masterKey.getKey();

		ctx.attr(MASTER_KEY_INFO).set(KeyList.get(sn));

		logger.debug("Prepare to build master key info...");
		CKeyInfo cKeyInfo = new CKeyInfo(authInfo, sn);
		byte[] data = cKeyInfo.setMasterKey(keyIndex, key).build();

		write(data);
	}
	
	private void downloadingValidationMasterKeyInfo() throws Exception {
		KeyInfo keyInfo = ctx.attr(MASTER_KEY_INFO).get();
		List<MasterKey> list = keyInfo.getMasterKeys();
		if (list == null || list.size() < 1) {
			return;
		}
		for (MasterKey masterKey : list) {
			downloadingValidationMasterKeyInfo(masterKey);
		}
	}
	
	private void downloadingValidationMasterKeyInfo(MasterKey masterKey) throws Exception {
		logger.debug("Key index: " + masterKey.getKeyIndex());
		logger.debug("Key: " + CommonUtils.toHex(masterKey.getKey()));

		byte[] masterKeyId = new byte[] { (byte) masterKey.getKeyIndex() };
		byte[] userKeyId = new byte[] { 0x02 };
		byte[] userKeyType = new byte[] { 0x02 };

		byte[] plainUserKey = CommonUtils.randomString(16).getBytes();
		logger.debug("Plain User Key: " + CommonUtils.toHex(plainUserKey));
		byte[] encryptUserKey = CertUtils.doubleDesEncrypt(masterKey.getKey(), plainUserKey);
		logger.debug("Encrypt User Key: " + CommonUtils.toHex(encryptUserKey));

		byte[] checkValue = CommonUtils.subBytes(CertUtils.doubleDesEncrypt(plainUserKey,
				new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}), 0, 8);
		logger.debug("Check Value: " + CommonUtils.toHex(checkValue));
		byte[] checkValueLen = ByteConvert.int2byte2(checkValue.length);

		byte[] userKey = encryptUserKey;
		logger.debug("User Key: " + CommonUtils.toHex(userKey));
		byte[] userKeyLen = ByteConvert.int2byte2(userKey.length);

		byte[] msgData = CommonUtils.randomString(16).getBytes();
		logger.debug("Msg Data: " + CommonUtils.toHex(msgData));
		byte[] msgDataLen = ByteConvert.int2byte2( msgData.length);

		byte[] cipherData = CertUtils.doubleDesEncrypt(plainUserKey, msgData);
		logger.debug("Cipher Data: " + CommonUtils.toHex(cipherData));
		byte[] cipherDataLen = ByteConvert.int2byte2(cipherData.length);

		byte[] result = CommonUtils.append(masterKeyId, userKeyId, userKeyType,
				userKeyLen, userKey,
				checkValueLen, checkValue,
				msgDataLen, msgData,
				cipherDataLen, cipherData);
		write(result);
	}
	
	private void buildTransportKey() throws Exception {
		AuthInfo authInfo = new AuthInfo(CommonUtils.subBytes(inData, 1));
		// Get transport key from configuration file by sn.
		String sn = new String(authInfo.getSN());
		logger.debug("Sn: " + sn);
		KeyInfo keyInfo = KeyList.get(sn);
		if (keyInfo == null) {
			write(ByteConvert.int2byte2(0));
			return;
		}
		List<TransportKey> list = keyInfo.getTransportKeys();
		if (list == null || list.size() < 1) {
			write(ByteConvert.int2byte2(0));
			return;
		}
		write(ByteConvert.int2byte2(list.size()));
		for (TransportKey transportKey : list) {
			buildTransportKey(authInfo, sn, transportKey);
		}
	}
	
	private void buildTransportKey(AuthInfo authInfo, String sn, TransportKey transportKey) throws Exception {
		logger.debug("Sn: " + sn);
		// Get transport key from keylist.txt file
		int keyIndex = transportKey.getKeyIndex();
		byte[] key = transportKey.getKey();

		ctx.attr(TRANSPORT_KEY_INFO).set(KeyList.get(sn));

		logger.debug("Prepare to build transport key info...");
		CKeyInfo cKeyInfo = new CKeyInfo(authInfo, sn);
		byte[] data = cKeyInfo.setTransportKey(keyIndex, key).build();

		write(data);
	}
	
	private void downloadingValidationTransportKeyInfo() throws Exception {
		KeyInfo keyInfo = ctx.attr(TRANSPORT_KEY_INFO).get();
		List<TransportKey> list = keyInfo.getTransportKeys();
		if (list == null || list.size() < 1) {
			return;
		}
		for (TransportKey transportKey : list) {
			downloadingValidationTransportKeyInfo(transportKey);
		}
	}
	
	private void downloadingValidationTransportKeyInfo(TransportKey transportKey) throws Exception {
		logger.debug("Key index: " + transportKey.getKeyIndex());
		logger.debug("Key: " + CommonUtils.toHex(transportKey.getKey()));

		byte[] transportKeyId = new byte[] { (byte) transportKey.getKeyIndex() };
		byte[] userKeyId = new byte[] { 0x02 };
		byte[] userKeyType = new byte[] { 0x02 };

		byte[] plainUserKey = CommonUtils.randomString(16).getBytes();
		logger.debug("Plain User Key: " + CommonUtils.toHex(plainUserKey));
		byte[] encryptUserKey = CertUtils.doubleDesEncrypt(transportKey.getKey(), plainUserKey);
		logger.debug("Encrypt User Key: " + CommonUtils.toHex(encryptUserKey));

		byte[] checkValue = CommonUtils.subBytes(CertUtils.doubleDesEncrypt(plainUserKey,
				new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}), 0, 8);
		logger.debug("Check Value: " + CommonUtils.toHex(checkValue));
		byte[] checkValueLen = ByteConvert.int2byte2(checkValue.length);

		byte[] userKey = encryptUserKey;
		logger.debug("User Key: " + CommonUtils.toHex(userKey));
		byte[] userKeyLen = ByteConvert.int2byte2(userKey.length);

		byte[] msgData = CommonUtils.randomString(16).getBytes();
		logger.debug("Msg Data: " + CommonUtils.toHex(msgData));
		byte[] msgDataLen = ByteConvert.int2byte2( msgData.length);

		byte[] cipherData = CertUtils.doubleDesEncrypt(plainUserKey, msgData);
		logger.debug("Cipher Data: " + CommonUtils.toHex(cipherData));
		byte[] cipherDataLen = ByteConvert.int2byte2(cipherData.length);

		byte[] result = CommonUtils.append(transportKeyId, userKeyId, userKeyType,
				userKeyLen, userKey,
				checkValueLen, checkValue,
				msgDataLen, msgData,
				cipherDataLen, cipherData);
		write(result);
	}
	
	private void buildDukptKey() throws Exception {
		AuthInfo authInfo = new AuthInfo(CommonUtils.subBytes(inData, 1));
		// Get dukpt key from configuration file by sn.
		String sn = new String(authInfo.getSN());
		logger.debug("Sn: " + sn);
		KeyInfo keyInfo = KeyList.get(sn);
		if (keyInfo == null) {
			write(ByteConvert.int2byte2(0));
			return;
		}
		List<DukptKey> list = keyInfo.getDukptKeys();
		if (list == null || list.size() < 1) {
			write(ByteConvert.int2byte2(0));
			return;
		}
		write(ByteConvert.int2byte2(list.size()));
		for (DukptKey dukptKey : list) {
			buildDukptKey(authInfo, sn, dukptKey);
		}
	}

	private void buildDukptKey(AuthInfo authInfo, String sn, DukptKey dukptKey) throws Exception {
		logger.debug("Sn: " + sn);

		logger.debug("Prepare to build dukpt key info...");
		CKeyInfo cKeyInfo = new CKeyInfo(authInfo, sn);

//		byte[] ksn = CommonUtils.toBytes("FFFF9876543210E0");
//		int counter = 0;
//		byte[] key = CommonUtils.toBytes("6AC292FAA1315B4D858AB3A3D7D5933A");
//		byte[] data = cKeyInfo.setDukptKey(2, 2, ksn, counter, key).build();

		byte[] data = cKeyInfo.setDukptKey(dukptKey.getKeyIndex(), dukptKey.getReserved(), dukptKey.getKsn(), dukptKey.getCounter(), dukptKey.getKey()).build();

		write(data);
	}

}
