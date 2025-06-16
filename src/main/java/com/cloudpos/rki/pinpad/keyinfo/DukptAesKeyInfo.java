package com.cloudpos.rki.pinpad.keyinfo;

import com.cloudpos.rki.util.ByteConvert;
import com.cloudpos.rki.util.CommonUtils;

public class DukptAesKeyInfo extends PKeyInfo {
    private static final int LEN_KEY_USAGE = 1;
    private static final int LEN_INITIAL_KEY_LEN = 1;
    private static final int LEN_KSN = 8;
    private static final int LEN_COUNTER = 4;
    private static final int LEN_INITIAL_KEY = 32;

    // 0 PIN key 1 MAC Key 2 Data Key
    private byte keyUsage;
    private byte initialKeyLen;
    private byte[] ksn;
    private byte[] counter;
    private byte[] initialKey;
    
    public DukptAesKeyInfo(String sn, String rid) {
    	super(sn, rid);
    	 /*0 : DUKPT, 1 : TDUKPT, 2 : MK, 3 : TK, 5 : Dukpt2009, 6 : DukptAES*/
		this.keyType = 6;
	}
    
    @Override
    public void parse0(byte[] data) {
        super.parse0(data);

        this.keyUsage = data[offset];
        this.offset += 1;
        
        this.initialKeyLen = data[offset];
        this.offset += 1;
        
        this.ksn = CommonUtils.subBytes(data, offset, LEN_KSN);
        this.offset += LEN_KSN;

        this.counter = CommonUtils.subBytes(data, offset, LEN_COUNTER);
        this.offset += LEN_COUNTER;

        this.initialKey = CommonUtils.subBytes(data, offset, LEN_INITIAL_KEY);
        this.offset += LEN_INITIAL_KEY;
    }

    public byte[] build(int keyIndex, int keyUsage, byte[] ksn, int counter, byte[] initialKey) {
    	return build(keyIndex, keyUsage, ksn, ByteConvert.int2byte4(counter), initialKey);
    }

    public byte[] build(int keyIndex, int keyUsage, byte[] ksn, byte[] counter, byte[] initialKey) {
    	if (keyIndex < 0 || keyIndex > 49) {
    		throw new IllegalArgumentException("Key index must be between 0 and 49. But current key index is [" + keyIndex + "]");
    	}
    	// support dukpt in format TDES/AES.
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
    	byte[] result = new byte[LEN_KEY_TYPE + LEN_KEY_INDEX + LEN_KEY_USAGE + LEN_INITIAL_KEY_LEN + LEN_KSN + LEN_COUNTER + LEN_INITIAL_KEY];
    	int index = 0;
    	CommonUtils.append(keyType, result, index);
    	index += LEN_KEY_TYPE;

    	CommonUtils.append((byte) keyIndex, result, index);
    	index += LEN_KEY_INDEX;

    	result[index] = (byte) keyUsage;
    	index += LEN_KEY_USAGE;
    	
    	result[index] = (byte) initialKey.length;
    	index += LEN_INITIAL_KEY_LEN;

    	CommonUtils.append(ksn, result, index);
    	index += LEN_KSN;

    	CommonUtils.append(counter, result, index);
    	index += LEN_COUNTER;

    	CommonUtils.append(initialKey, result, index);
    	index += LEN_INITIAL_KEY;

    	return result;
    }

    public byte getKeyUsage() {
		return keyUsage;
	}
    
    public byte getInitialKeyLen() {
		return initialKeyLen;
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