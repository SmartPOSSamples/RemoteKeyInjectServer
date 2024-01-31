package com.cloudpos.rki.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;

/**
 * 有新连接进入的同时会创建一个新的类实例
 * @author lizhou
 */
public class CommandHandler extends ChannelInboundHandlerAdapter {
	private static final Logger logger = LoggerFactory.getLogger(CommandHandler.class);
	private MessageManager messageManager = MessageManager.getSingleton();

	private ByteArrayOutputStream dataBuf;

	public CommandHandler() {
		logger.debug("Instance address: " + this);
	}

	@Override
	public void channelActive(final ChannelHandlerContext ctx) {
		ctx.pipeline().get(SslHandler.class).handshakeFuture().addListener(new GenericFutureListener<Future<Channel>>() {
			public void operationComplete(Future<Channel> future) throws Exception {
				dataBuf = new ByteArrayOutputStream();
			}
		});
	}

	@Override
	public void channelInactive(final ChannelHandlerContext ctx) {
		ctx.close();
		logger.debug("Close connection...");
	}

	@Override
	public void channelRead(final ChannelHandlerContext ctx, final Object msg) {
		ByteBuf in = (ByteBuf) msg;
		try {
			byte[] bytes = new byte[in.readableBytes()];
			in.readBytes(bytes);
			dataBuf.write(bytes);
		} catch (IOException e) {
			logger.error("", e);
		} finally {
			ReferenceCountUtil.release(msg);
		}
	}

	@Override
	public void channelReadComplete(final ChannelHandlerContext ctx) {
		if (dataBuf == null || dataBuf.size() < 1) {
			return;
		}
		MessagePack messagePack = new MessagePack(dataBuf.toByteArray(), ctx);
		messageManager.addSocketMessage(messagePack);

		dataBuf = new ByteArrayOutputStream();
	}

	@Override
	public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
		logger.error("", cause);
		ctx.close();
	}
}
