package com.cloudpos.rki.req;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alibaba.fastjson2.JSON;
import com.cloudpos.rki.pinpad.AuthInfo;
import com.cloudpos.rki.util.CertUtils;
import com.cloudpos.rki.util.CommonUtils;
import com.cloudpos.rki.util.ConfigUtil;
import com.cloudpos.rki.util.KeyList.KeyInfo;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.AttributeKey;

public abstract class KeyPack implements Runnable {
	protected static final Logger logger = LoggerFactory.getLogger(KeyPack.class);
	
	protected static final AttributeKey<KeyInfo> MASTER_KEY_INFO = AttributeKey.<KeyInfo>valueOf("MASTER_KEY_INFO");
	protected static final AttributeKey<KeyInfo> TRANSPORT_KEY_INFO = AttributeKey.<KeyInfo>valueOf("TRANSPORT_KEY_INFO");
	
	protected byte[] inData;
	protected ChannelHandlerContext ctx;
	protected String rid;
	
	private static X509Certificate rootCert;
	
	public void loadRootCert() {
		
	}
	
	protected AuthInfo getAndCheckCert() throws Exception {
		AuthInfo authInfo = new AuthInfo(CommonUtils.subBytes(inData, 1));
		// Check whether the terminal certificate is correct.
		if (!verify(authInfo.getCert())) {
			logger.error("{} - Verify failed. ", rid);
		}
		return authInfo;
	}
	
	private boolean verify(X509Certificate terminalCert) {
		try {
			rootCert = CertUtils.readPemCert(new FileInputStream(new File(ConfigUtil.getPinpadRootCert())));
			terminalCert.verify(rootCert.getPublicKey());
			return true;
		} catch (Exception e) {
			logger.error("Load root certificate error. ", e);
		}
		return false;
	}
	
	@Override
	public void run() {
		try {
			logger.debug("{} - Read  data: {}", rid, CommonUtils.toHex(inData));
			byte reqType = inData[0];
			if (reqType == 0x01) { // Request to inject master key
				this.inject();
				

			} else if (reqType == 0x02) { // Request to validate master key
				this.validate();

			} else if (reqType == 0x03) { // Request to inject transport key
				this.inject();
				
			} else if (reqType == 0x04) { // Request to validate transport key
				this.validate();

			} else if (reqType == 0x05) { // Request to inject dukpt key
				this.inject();

			}
		} catch (Exception e) {
			logger.error("", e);
		}
	}

	public void inject() throws Exception {
		
	}
	
	public void validate() throws Exception {
		
	}
	
	public KeyPack set(byte[] inData, ChannelHandlerContext ctx, String rid) {
		this.inData = inData;
		this.ctx = ctx;
		
		this.rid = rid;
		return this;
	}
	
	protected void write(Result result) throws InterruptedException {
		write(JSON.toJSONString(result).getBytes(StandardCharsets.UTF_8));
	}
	
	private void write(byte[] data) throws InterruptedException {
		logger.debug("{} - Write data. len: {}, content: {}{}", rid, data.length, CommonUtils.toHex(CommonUtils.intTo2Bytes(data.length)), CommonUtils.toHex(data));

		ByteBuf byteBuf = Unpooled.copiedBuffer(CommonUtils.intTo2Bytes(data.length), data);
		ctx.writeAndFlush(byteBuf).sync();
	}
	
	protected static class Result {
		public static final int SUCCESS = 1;
		public static final int NO_AVAILABLE_KEY = 2;
		
		private int status;
		private String desc;
		private List<RKey> keys = new ArrayList<>();
		
		public Result(int status) {
			this.status = status;
		}
		public Result(int status, String desc) {
			this.status = status;
			this.desc = desc;
		}
		
		public int getStatus() {
			return status;
		}
		public void setStatus(int status) {
			this.status = status;
		}
		public String getDesc() {
			return desc;
		}
		public void setDesc(String desc) {
			this.desc = desc;
		}
		public List<RKey> getKeys() {
			return keys;
		}
		public void setKeys(List<RKey> keys) {
			this.keys = keys;
		}
		public Result addKeyData(RKey key) {
			keys.add(key);
			return this;
		}
	}
	
	protected static class RKey {
		private String key;
		private boolean aes;
		public String getKey() {
			return key;
		}
		public void setKey(String key) {
			this.key = key;
		}
		public boolean isAes() {
			return aes;
		}
		public RKey setAes(boolean aes) {
			this.aes = aes;
			return this;
		}
		public RKey setKeyData(byte[] data) {
			this.key = CommonUtils.toHex(data);
			return this;
		}
	}
}
