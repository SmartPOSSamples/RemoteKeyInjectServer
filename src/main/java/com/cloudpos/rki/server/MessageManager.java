package com.cloudpos.rki.server;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MessageManager {
	private static final Logger logger = LoggerFactory.getLogger(MessageManager.class);
	private static final MessageManager messageManager = new MessageManager();

	private LinkedBlockingQueue<MessagePack> receivedQueen = new LinkedBlockingQueue<MessagePack>(1000);

	private ExecutorService pool;

	private MessageManager() {
		pool = Executors.newFixedThreadPool(8);
		new Thread(new QueueMonitor()).start();
	}

	public static MessageManager getSingleton() {
		return messageManager;
	}

	private class QueueMonitor implements Runnable {
		public void run() {
			while (true) {
				try {
					MessagePack message = receivedQueen.poll(3,	TimeUnit.SECONDS);
					if (message == null) {
						continue;
					}
					pool.submit(message);
				} catch (Exception e) {
					logger.error("Get message error:", e);
				}
			}
		}
	}

	public void addSocketMessage(MessagePack message) {
		if (message == null) {
			return;
		}
		for (boolean success = false; !success;) {
			try {
				success = receivedQueen.offer(message, 3, TimeUnit.SECONDS);
			} catch (Exception e) {
				logger.error("offer message error:", e);
			}
		}
	}
}
