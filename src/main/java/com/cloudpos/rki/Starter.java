package com.cloudpos.rki;

import java.io.IOException;

import org.apache.logging.log4j.core.config.ConfigurationSource;
import org.apache.logging.log4j.core.config.Configurator;

import com.cloudpos.rki.server.InjectServer;

public class Starter {

	public static void main(String[] args) throws Exception {
		loadLog4j();

		InjectServer injectServer = new InjectServer();
		injectServer.initPinPadKeyStore();

		injectServer.initSSLServer();
	}

	private static void loadLog4j() throws IOException {
		System.out.println("Loading log4j config file...");

		
		ConfigurationSource source = new ConfigurationSource(InjectServer.class.getClassLoader().getResourceAsStream("resources/log4j2.xml"));
		Configurator.initialize(null, source); 

		System.out.println("Loading log4j config file complete");
	}
}
