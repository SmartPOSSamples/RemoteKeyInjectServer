package com.cloudpos.rki.pinpad.keyinfo;

public class TransportKeyInfo extends MasterKeyInfo {

	public TransportKeyInfo(String sn) {
		super(sn);
		this.keyType = KEY_TYPE_TRANSPORT;
	}

	public byte[] buildTransportKey(int keyIndex, int keyLen, byte reversed, byte[] key) {
    	return build(keyIndex, keyLen, reversed, key);
    }

    public byte[] buildTransportKey(int keyIndex, byte reversed, byte[] key) {
    	return buildTransportKey(keyIndex, key.length, reversed, key);
    }

    public byte[] buildTransportKey(int keyIndex, byte[] key) {
    	return buildTransportKey(keyIndex, (byte) 0, key);
    }

    public byte[] buildTransportKey(byte[] key) {
    	return buildTransportKey(9, key);
    }
}
