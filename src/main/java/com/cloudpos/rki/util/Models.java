package com.cloudpos.rki.util;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.LineIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Models {
	private static final Logger logger = LoggerFactory.getLogger(Models.class);
	private static Map<String, Pattern> map = new LinkedHashMap<String, Pattern>();

	static {
		try {
			LineIterator iter = FileUtils.lineIterator(new File("models.txt"), "UTF-8");
			while (iter.hasNext()) {
				String line = iter.next();
				if (line == null || line.trim().length() < 1) {
					continue;
				}
				if (line.startsWith("#")) {
					continue;
				}
				String[] ss = line.split("=", 2);
				
				String model = ss[0].replaceAll("\t", "").trim();
				Pattern pattern = Pattern.compile(ss[1].replaceAll("\t", "").trim());

				map.put(model, pattern);
			}
			iter.close();
		} catch (Exception e) {
			logger.error("", e);
		}
	}

	public static String getModel(String sn) {
		for (Entry<String, Pattern> entry : map.entrySet()) {
			if (entry.getValue().matcher(sn).matches()) {
				return entry.getKey();
			}
		}
		return null;
		
	}
}
