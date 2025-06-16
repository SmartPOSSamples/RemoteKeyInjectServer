package com.cloudpos.rki.server;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cloudpos.rki.req.DukptKeyPack;
import com.cloudpos.rki.req.KeyPack;
import com.cloudpos.rki.req.MasterKeyPack;
import com.cloudpos.rki.req.TransportKeyPack;

import io.netty.channel.ChannelHandlerContext;

public class MessageDispatch {
	private static final Logger logger = LoggerFactory.getLogger(MessageDispatch.class);
	private static MessageDispatch instance = new MessageDispatch();
	
	private ThreadPoolExecutor pool;

	private MessageDispatch() {
		pool = new ThreadPoolExecutor(2, 32, 5, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
	}

	public void addSocketMessage(Runnable message) {
		if (message == null) {
			logger.error("Invalid message. null");
			return;
		}
		pool.submit(message);
	}
	
	public static void dispatch(byte[] inData, ChannelHandlerContext ctx, String rid) {
		instance.addSocketMessage(dispatch0(inData, ctx, rid));
	}

	private static KeyPack dispatch0(byte[] inData, ChannelHandlerContext ctx, String rid) {
		try {
			byte reqType = inData[0];
			if (reqType == 0x01) { // Request to inject master key
				return new MasterKeyPack().set(inData, ctx, rid);

			} else if (reqType == 0x02) { // Request to validate master key
				return new MasterKeyPack().set(inData, ctx, rid);

			} else if (reqType == 0x03) {
				return new TransportKeyPack().set(inData, ctx, rid);
				
			} else if (reqType == 0x04) { // Request to validate transport key
				return new TransportKeyPack().set(inData, ctx, rid);

			} else if (reqType == 0x05) { // Request to inject dukpt key
				return new DukptKeyPack().set(inData, ctx, rid);

			}
		} catch (Exception e) {
			logger.error("{} - ", rid, e);
		}
		return null;
	}
	
	
	
}
