package com.cloudpos.rki.pinpad.keyinfo;

import com.cloudpos.rki.util.CommonUtils;
import com.cloudpos.rki.util.ConfigUtil;
import com.cloudpos.rki.util.Models;

public class MasterKeyInfo extends PKeyInfo {
	protected static final int LEN_KEY_LEN = 1;
	protected static final int LEN_RESERVED = 1;
	
	protected static final int LEN_KEY = 24;

	protected byte keyLength;
	protected byte reserved;
	protected byte[] key;
	// Q1 --> 24
	// Q2 Q1v2 K2 --> 32 
	protected int lengthKey = LEN_KEY;

	public MasterKeyInfo(String sn) {
		super(sn);
		this.keyType = KEY_TYPE_MASTER;
		
		if (sn != null) {
			String model = Models.getModel(sn);
			if (model != null && ConfigUtil.contain(model.trim())) {
				lengthKey = ConfigUtil.getKeyLen(model.trim());
				logger.debug("sn: {}, model: {}, lenght key: {}", sn, model, lengthKey);
			}
		}
	}

    @Override
    protected void parse0(byte[] data) {
        super.parse0(data);

        this.keyLength = data[offset];
        this.offset += LEN_KEY_LEN;

        this.reserved = data[offset];
        this.offset += LEN_RESERVED;

        this.key = CommonUtils.subBytes(data, offset, lengthKey);
        this.offset += lengthKey;
    }

    public byte[] buildMasterKey(int keyIndex, int keyLen, byte reversed, byte[] key) {
    	return build(keyIndex, keyLen, reversed, key);
    }

    public byte[] buildMasterKey(int keyIndex, byte reversed, byte[] key) {
    	return buildMasterKey(keyIndex, key.length, reversed, key);
    }

    /**
     * Create master key info
     * @param keyIndex 0-9
     * @param key master key buffer
     * @return
     */
    public byte[] buildMasterKey(int keyIndex, byte[] key) {
    	return buildMasterKey(keyIndex, (byte) 0, key);
    }

    public byte[] buildMasterKey(byte[] key) {
    	return buildMasterKey(9, key);
    }

    protected byte[] build(int keyIndex, int keyLen, byte reversed, byte[] key) {
    	if (keyIndex < 0 || keyIndex > 49) {
    		throw new IllegalArgumentException("Key index must be between 0 and 49. But current key index is [" + keyIndex + "]");
    	}
    	if (key.length != 16 && key.length != 24 && key.length != 32) {
    		throw new IllegalArgumentException("The key length must be 16, 24 or 32. But the using key length is [" + key.length + "]");
    	}
    	byte[] result = new byte[LEN_KEY_TYPE + LEN_KEY_INDEX + LEN_KEY_LEN + LEN_RESERVED + lengthKey];
    	int index = 0;
    	CommonUtils.append(keyType, result, index);
    	index += LEN_KEY_TYPE;

    	CommonUtils.append((byte) keyIndex, result, index);
    	index += LEN_KEY_INDEX;

    	CommonUtils.append((byte) keyLen, result, index);
    	index += LEN_KEY_LEN;

    	CommonUtils.append(reversed, result, index);
    	index += LEN_RESERVED;

    	CommonUtils.append(key, result, index);
    	index += lengthKey;

    	return result;
    }

    public byte getKeyLength() {
        return keyLength;
    }

    public byte getReserved() {
        return reserved;
    }

    public byte[] getKey() {
        return key;
    }
}