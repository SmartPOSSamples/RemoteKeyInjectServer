package com.cloudpos.rki.util;

import java.io.InputStream;
import java.util.Random;

import org.bouncycastle.util.encoders.Hex;

public class CommonUtils {
	private static final char[] DEFAULT_CANDIDATES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123467890+-*/".toCharArray();
	private static final char[] DEFAULT_ALPHANUMBER = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123467890".toCharArray();
	private static final char[] DEFAULT_NUMBER = "0123467890".toCharArray();
	
	public static InputStream loadClassPathResource(String name) {
		return CommonUtils.class.getResourceAsStream(name);
	}

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
		return randomString(DEFAULT_CANDIDATES, length);
	}
	
	public static String randomAlphaNumber(int length) {
		return randomString(DEFAULT_ALPHANUMBER, length);
	}
	
	public static String randomNumber(int length) {
		return randomString(DEFAULT_NUMBER, length);
	}

	public static String randomString(char[] arr, int length) {
		Random random = new Random();
		StringBuilder sb = new StringBuilder(length);
		for (int i = 0; i < length; i++) {
			sb.append(arr[random.nextInt(arr.length)]);
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
    
    public static void append(byte[] src, byte[] dest, int offset, int length) {
        System.arraycopy(src, 0, dest, offset, length);
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
    
    public static boolean in(int v, int...candidates) {
    	if (candidates == null) {
    		return false;
    	}
    	for (int i : candidates) {
    		if (i == v) {
    			return true;
    		}
    	}
    	return false;
    }
}
