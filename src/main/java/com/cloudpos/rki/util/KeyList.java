package com.cloudpos.rki.util;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.LineIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyList {
	private static final Logger logger = LoggerFactory.getLogger(KeyList.class);
	private static Map<String, KeyInfo> map = new LinkedHashMap<String, KeyInfo>();
	private static File keyFile = new File("keylist.txt");
	private static long lastModified = -1;

	static {
		loadKeyFile();
	}
	
	private static void loadKeyFile() {
		map.clear();
		try {
			LineIterator iter = FileUtils.lineIterator(keyFile, "UTF-8");
			while (iter.hasNext()) {
				String line = iter.next();
				if (line == null || line.trim().length() < 1) {
					continue;
				}
				if (line.startsWith("#")) {
					continue;
				}
				String[] ss = line.split("=", 2);


				String key = ss[0].trim();
				String[] ks = key.split("\\.");

				String sn = ks[1].trim();
				String keyType = ks[0].trim();

				KeyInfo keyBean = map.get(sn);
				if (keyBean == null) {
					keyBean = new KeyInfo();
				}
				map.put(sn, keyBean.setKeyInfo(keyType, ss[1].trim()));
			}
			iter.close();
			
			lastModified = keyFile.lastModified();
		} catch (Exception e) {
			logger.error("", e);
		}
	}

	public static KeyInfo get(String sn) {
		if (keyFile.lastModified() != lastModified) {
			logger.debug("Key file changed. Last modified: {}, new modified: {}", lastModified, keyFile.lastModified());
			loadKeyFile();
		}
		return map.get(sn);
	}

	public static class KeyInfo {
		private List<DukptKey> dukptKeys = new ArrayList<KeyList.DukptKey>();
		private List<MasterKey> masterKeys = new ArrayList<KeyList.MasterKey>();
		private List<TransportKey> transportKeys = new ArrayList<KeyList.TransportKey>();

		public KeyInfo setKeyInfo(String keyType, String keyStr) {
			if ("1".equals(keyType)) {
				String[] vs = keyStr.split(",", 5);
				int keyIndex = Integer.parseInt(vs[0].trim());
//				int reserved = Integer.parseInt(vs[1].trim());
				int reserved = 0xff;
				int counter = Integer.parseInt(vs[2].trim());
				byte[] ksn = CommonUtils.toBytes(vs[3].trim());
				byte[] key = CommonUtils.toBytes(vs[4].trim());

				this.dukptKeys.add(new DukptKey(keyIndex, reserved, counter, ksn, key));

			} else if ("2".equals(keyType)) {
				String[] vs = keyStr.split(",", 2);
				this.masterKeys.add(new MasterKey(Integer.parseInt(vs[0].trim()), CommonUtils.toBytes(vs[1].trim())));

			} else if ("3".equals(keyType)) {
				String[] vs = keyStr.split(",", 2);
				this.transportKeys.add(new TransportKey(Integer.parseInt(vs[0].trim()), CommonUtils.toBytes(vs[1].trim())));
			}
			return this;
		}
		public List<DukptKey> getDukptKeys() {
			return dukptKeys;
		}
		public List<MasterKey> getMasterKeys() {
			return masterKeys;
		}
		public List<TransportKey> getTransportKeys() {
			return transportKeys;
		}
		
//		public DukptKey getDukptKey() {
//			return dukptKeys;
//		}
//		public MasterKey getMasterKey() {
//			return masterKeys;
//		}
//		public TransportKey getTransportKey() {
//			return transportKeys;
//		}
	}

	public static class DukptKey {
		private int keyIndex;
		private int reserved;
		private int counter;
		private byte[] ksn;
		private byte[] key;
		public DukptKey(int keyIndex, int reserved, int counter, byte[] ksn, byte[] key) {
			this.keyIndex = keyIndex;
			this.reserved = reserved;
			this.counter = counter;
			this.ksn = ksn;
			this.key = key;
		}
		public int getKeyIndex() {
			return keyIndex;
		}
		public int getReserved() {
			return reserved;
		}
		public int getCounter() {
			return counter;
		}
		public byte[] getKsn() {
			return ksn;
		}
		public byte[] getKey() {
			return key;
		}
	}

	public static class MasterKey {
		private int keyIndex;
		private byte[] key;
		public MasterKey(int keyIndex, byte[] key) {
			this.keyIndex = keyIndex;
			this.key = key;
		}
		public int getKeyIndex() {
			return keyIndex;
		}
		public byte[] getKey() {
			return key;
		}
	}

	public static class TransportKey extends MasterKey {
		public TransportKey(int keyIndex, byte[] key) {
			super(keyIndex, key);
		}
	}
}
