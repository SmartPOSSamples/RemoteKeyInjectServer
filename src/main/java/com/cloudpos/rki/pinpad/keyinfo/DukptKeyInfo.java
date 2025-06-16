package com.cloudpos.rki.pinpad.keyinfo;

import com.cloudpos.rki.util.ByteConvert;
import com.cloudpos.rki.util.CommonUtils;

public class DukptKeyInfo extends PKeyInfo {
    private static final int LEN_RESERVED = 2;
    private static final int LEN_KSN = 8;
    private static final int LEN_COUNTER = 4;
    private static final int LEN_INITIAL_KEY = 16;

    // 0 PIN key 1 MAC Key 2 Data Key
    private byte[] reversed;
    private byte[] ksn;
    private byte[] counter;
    private byte[] initialKey;
    
    private int initialKeyLen = LEN_INITIAL_KEY;

    public DukptKeyInfo(String sn, String rid) {
    	super(sn, rid);
		this.keyType = KEY_TYPE_DUKPT;
	}
    
    @Override
    public void parse0(byte[] data) {
        super.parse0(data);

        this.reversed = CommonUtils.subBytes(data, offset, LEN_RESERVED);
        this.offset += LEN_RESERVED;

        this.ksn = CommonUtils.subBytes(data, offset, LEN_KSN);
        this.offset += LEN_KSN;

        this.counter = CommonUtils.subBytes(data, offset, LEN_COUNTER);
        this.offset += LEN_COUNTER;

        this.initialKey = CommonUtils.subBytes(data, offset, LEN_INITIAL_KEY);
        this.offset += LEN_INITIAL_KEY;
    }

    public byte[] build(int keyIndex, int reserved, byte[] ksn, int counter, byte[] initialKey) {
    	return build(keyIndex, ByteConvert.int2byte2(reserved, false), ksn, ByteConvert.int2byte4(counter), initialKey);
    }

    public byte[] build(int keyIndex, byte[] reserved, byte[] ksn, byte[] counter, byte[] initialKey) {
    	if (keyIndex < 0 || keyIndex > 49) {
    		throw new IllegalArgumentException("Key index must be between 0 and 49. But current key index is [" + keyIndex + "]");
    	}
    	if (reserved.length != 2) {
    		throw new IllegalArgumentException("The reserved length must be 2. But current reserved length is [" + reserved.length + "]");
    	}
    	if (ksn.length != 8) {
    		throw new IllegalArgumentException("The ksn length must be 8. But current ksn length is [" + ksn.length + "]");
    	}
    	if (counter.length != 4) {
    		throw new IllegalArgumentException("The counter length must be 4. But current counter length is [" + counter.length + "]");
    	}
    	// key 3DES: 16. key AES: 16 24 32
    	if (!CommonUtils.in(initialKey.length, 16, 24, 32)) {
    		throw new IllegalArgumentException("The key length should be 16/24/32. But current key length is [" + initialKey.length + "]");
    	}
    	byte[] result = new byte[LEN_KEY_TYPE + LEN_KEY_INDEX + LEN_RESERVED + LEN_KSN + LEN_COUNTER + initialKeyLen];
    	int index = 0;
    	CommonUtils.append(keyType, result, index);
    	index += LEN_KEY_TYPE;

    	CommonUtils.append((byte) keyIndex, result, index);
    	index += LEN_KEY_INDEX;

    	CommonUtils.append(reserved, result, index);
    	index += LEN_RESERVED;

    	CommonUtils.append(ksn, result, index);
    	index += LEN_KSN;

    	CommonUtils.append(counter, result, index);
    	index += LEN_COUNTER;

    	CommonUtils.append(initialKey, result, index);
    	index += initialKeyLen;

    	return result;
    }

    public byte[] getReversed() {
        return reversed;
    }

    public byte[] getKsn() {
        return ksn;
    }

    public byte[] getCounter() {
        return counter;
    }

    public byte[] getInitialKey() {
        return initialKey;
    }
}