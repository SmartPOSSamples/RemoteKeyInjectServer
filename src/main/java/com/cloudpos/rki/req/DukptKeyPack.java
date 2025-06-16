package com.cloudpos.rki.req;

import java.util.List;

import com.cloudpos.rki.pinpad.AuthInfo;
import com.cloudpos.rki.pinpad.CKeyInfo;
import com.cloudpos.rki.util.KeyList;
import com.cloudpos.rki.util.KeyList.DukptKey;
import com.cloudpos.rki.util.KeyList.KeyInfo;

public class DukptKeyPack extends KeyPack {
	
	@Override
	public void inject() throws Exception {
		AuthInfo authInfo = getAndCheckCert();
		// Get dukpt key from configuration file by sn.
		String sn = new String(authInfo.getSN());
		logger.debug("{} - Sn: {}", rid, sn);
		KeyInfo keyInfo = KeyList.get(sn);
		if (keyInfo == null) {
			write(new Result(Result.NO_AVAILABLE_KEY, "No available key"));
			return;
		}
		List<DukptKey> list = keyInfo.getDukptKeys();
		if (list == null || list.size() < 1) {
			write(new Result(Result.NO_AVAILABLE_KEY, "No available key"));
			return;
		}
		Result result = new Result(Result.SUCCESS, "Get key success");
		for (DukptKey dukptKey : list) {
			RKey key = buildDukptKey(authInfo, sn, dukptKey);
			result.addKeyData(key);
		}
		write(result);
	}
	
	private RKey buildDukptKey(AuthInfo authInfo, String sn, DukptKey dukptKey) throws Exception {
		logger.debug("{} - Prepare to build dukpt key info...", rid);
		CKeyInfo cKeyInfo = new CKeyInfo(authInfo, sn).setAes(dukptKey.isAes());

//		byte[] ksn = CommonUtils.toBytes("FFFF9876543210E0");
//		int counter = 0;
//		byte[] key = CommonUtils.toBytes("6AC292FAA1315B4D858AB3A3D7D5933A");
//		byte[] data = cKeyInfo.setDukptKey(2, 2, ksn, counter, key).build();

		byte[] data = null;
		if (dukptKey.isAes()) {
			data = cKeyInfo.setDukptAesKey(dukptKey.getKeyIndex(), dukptKey.getReserved(), dukptKey.getKsn(), dukptKey.getCounter(), dukptKey.getKey()).build();
		} else {
			data = cKeyInfo.setDukptKey(dukptKey.getKeyIndex(), dukptKey.getReserved(), dukptKey.getKsn(), dukptKey.getCounter(), dukptKey.getKey()).build();
		}
		return new RKey().setAes(dukptKey.isAes()).setKeyData(data);
	}
	
}
