package com.cloudpos.rki.pinpad.keyinfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Plain Key info structure.
 * @author lizhou
 */
public abstract class PKeyInfo {
	protected static final Logger logger = LoggerFactory.getLogger(PKeyInfo.class);
    protected static final int LEN_KEY_TYPE = 1;
    protected static final int LEN_KEY_INDEX = 1;

    protected static final byte KEY_TYPE_DUKPT = 1;
    protected static final byte KEY_TYPE_MASTER = 2;
    protected static final byte KEY_TYPE_TRANSPORT = 3;

    protected int offset = 0;
    protected byte keyType;
    protected byte keyIndex;
    
    protected String sn;
    public PKeyInfo(String sn) {
		this.sn = sn;
	}

    public static PKeyInfo parse(byte[] data) {
        byte keyType = data[0];
        PKeyInfo keyInfo = null;
        if (KEY_TYPE_DUKPT == keyType) {
            keyInfo = new DukptKeyInfo(null);
            
        } else if (KEY_TYPE_MASTER == keyType) {
        	keyInfo = new MasterKeyInfo(null);
        	
        } else if (KEY_TYPE_TRANSPORT == keyType) {
        	keyInfo = new TransportKeyInfo(null);
        }
        keyInfo.parse0(data);
        return keyInfo;
    }

    protected void parse0(byte[] data) {
        this.keyType = data[offset];
        this.offset += LEN_KEY_TYPE;

        this.keyIndex = data[offset];
        this.offset += LEN_KEY_INDEX;
    }

    public byte getKeyType() {
        return keyType;
    }

    public byte getKeyIndex() {
        return keyIndex;
    }
}
