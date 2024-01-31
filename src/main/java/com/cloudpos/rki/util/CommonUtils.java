package com.cloudpos.rki.util;

import java.util.Random;

import org.bouncycastle.util.encoders.Hex;

public class CommonUtils {

	public static byte[] intTo2Bytes(int i) {
		byte[] bs = new byte[2];
		bs[0] = (byte) (i >> 8 & 0xff);
		bs[1] = (byte) (i & 0xff);
		return bs;
	}

	public static int byte2ToInt(byte[] src, int offset) {
		if (null == src || offset < 0 || offset > src.length) {
			throw new NullPointerException("invalid byte array ");
		}
		if ((src.length - offset) < 2) {
			throw new IndexOutOfBoundsException("invalid len: " + src.length);
		}
		return ((src[offset + 0] & 0xff) << 8 | (src[offset + 1] & 0xff));
	}

	public static String randomString(int length) {
		char[] cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123467890+-*/".toCharArray();
		Random random = new Random();
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < length; i++) {
			sb.append(cs[random.nextInt(cs.length)]);
		}
		return sb.toString();
	}

	public static String toHex(byte[] src) {
		byte[] data = Hex.encode(src);
		return new String(data);
	}

	public static byte[] toBytes(String hex) {
		return Hex.decode(hex);
	}

	public static byte[] subBytes(byte[] src, int srcPos, int length) {
        byte[] bs = new byte[length];
        System.arraycopy(src, srcPos, bs, 0, length);
        return bs;
    }

	public static byte[] subBytes(byte[] src, int srcPos) {
		int length = src.length - srcPos;
        byte[] bs = new byte[length];
        System.arraycopy(src, srcPos, bs, 0, length);
        return bs;
    }

    public static void append(byte[] src, byte[] dest, int offset) {
        System.arraycopy(src, 0, dest, offset, src.length);
    }

    public static void append(byte src, byte[] dest, int offset) {
    	dest[offset] = src;
    }

    public static byte[] append(byte[]...srcs) {
    	int len = 0;
    	for (byte[] src : srcs) {
    		len += src.length;
    	}
    	byte[] result = new byte[len];
    	int pos = 0;
    	for (byte[] src : srcs) {
    		System.arraycopy(src, 0, result, pos, src.length);
    		pos += src.length;
    	}
    	return result;
    }
}
