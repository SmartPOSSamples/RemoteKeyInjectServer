package com.cloudpos.rki.server;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cloudpos.rki.util.ConfigUtil;
import com.cloudpos.rki.util.PinPadKeyStore;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslHandler;

public class InjectServer {
	private static final Logger logger = LoggerFactory.getLogger(InjectServer.class);
	private SSLContext sslContext;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public void initPinPadKeyStore() throws Exception {
		logger.info("Loading pin pad key store...");
		PinPadKeyStore.getInstance().load(
			ConfigUtil.getPinPadKeyStore(), ConfigUtil.getPinPadKeyStorePasswd(),
			ConfigUtil.getPinPadKeyAlias(), ConfigUtil.getPinPadKeyStorePasswd()
		);
	}

	public void initSSLServer() throws Exception {
		logger.debug("Start PinPad inject server");
		sslContext = SSLContext.getInstance("TLSv1.2");
//		sslContext = SSLContext.getInstance("SSLv3");
		sslContext.init(getKeyManagers(), getTrustManagers(), new SecureRandom());

		EventLoopGroup bossGroup = new NioEventLoopGroup();
		EventLoopGroup workerGroup = new NioEventLoopGroup();
		try {
			ServerBootstrap serverBootstrap = new ServerBootstrap();
			serverBootstrap.group(bossGroup, workerGroup);
			serverBootstrap.channel(NioServerSocketChannel.class);
			serverBootstrap.option(ChannelOption.SO_BACKLOG, 5000);
			serverBootstrap.option(ChannelOption.SO_KEEPALIVE, true);
			serverBootstrap.childOption(ChannelOption.SO_KEEPALIVE, true);
			serverBootstrap.childHandler(new ChannelInitializer<SocketChannel>() {
				@Override
				protected void initChannel(SocketChannel socketChannel) throws Exception {
					ChannelPipeline pipeline = socketChannel.pipeline();

					SSLEngine sslEngine = sslContext.createSSLEngine();
					sslEngine.setUseClientMode(false);
					sslEngine.setNeedClientAuth(true);

					SslHandler sslHandler = new SslHandler(sslEngine);
					sslHandler.setHandshakeTimeoutMillis(0);
					pipeline.addLast("ssl", sslHandler);

					pipeline.addLast(new CommandHandler());
				}
			});
			logger.info("begin bind port:" + ConfigUtil.getLocalPort());
			ChannelFuture channelFuture = serverBootstrap.bind(ConfigUtil.getLocalPort()).sync();
			logger.info("begin close Future syc");
			channelFuture.channel().closeFuture().sync();
			logger.info("end");
		} catch (InterruptedException e) {
			logger.error("", e);
		} finally {
			workerGroup.shutdownGracefully();
			bossGroup.shutdownGracefully();
		}
	}

	private KeyManager[] getKeyManagers() throws Exception {
		char[] password = ConfigUtil.getKeyStorePass().toCharArray();

		KeyStore keyStore = KeyStore.getInstance("JKS");
		File keystore = new File(ConfigUtil.getKeyStorePath());
		if (!keystore.exists()) {
			throw new NullPointerException(ConfigUtil.getKeyStorePath() + " do not exists");
		}
		keyStore.load(new FileInputStream(keystore), password);
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keyStore, password);
		return kmf.getKeyManagers();
	}

	private TrustManager[] getTrustManagers() throws Exception {
		char[] password = ConfigUtil.getTrustStorePass().toCharArray();

		KeyStore trustStore = KeyStore.getInstance("JKS");
		File keystore = new File(ConfigUtil.getTrustStorePath());
		if (!keystore.exists()) {
			throw new NullPointerException(ConfigUtil.getTrustStorePath() + " do not exists");
		}
		trustStore.load(new FileInputStream(keystore), password);
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(trustStore);
		return tmf.getTrustManagers();
	}

}
