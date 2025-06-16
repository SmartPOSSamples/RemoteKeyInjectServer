package com.cloudpos.rki.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cloudpos.rki.util.CommonUtils;

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
	private ByteArrayOutputStream dataBuf;
	private String rid;

	@Override
	public void channelActive(final ChannelHandlerContext ctx) {
		rid = CommonUtils.randomAlphaNumber(8);
		ctx.pipeline().get(SslHandler.class).handshakeFuture().addListener(new GenericFutureListener<Future<Channel>>() {
			public void operationComplete(Future<Channel> future) throws Exception {
				dataBuf = new ByteArrayOutputStream();
			}
		});
	}

	@Override
	public void channelInactive(final ChannelHandlerContext ctx) {
		ctx.close();
		logger.debug("{} - Close connection...", rid);
	}

	@Override
	public void channelRead(final ChannelHandlerContext ctx, final Object msg) {
		ByteBuf in = (ByteBuf) msg;
		try {
			byte[] bytes = new byte[in.readableBytes()];
			in.readBytes(bytes);
			dataBuf.write(bytes);
		} catch (IOException e) {
			logger.error("{} - ", rid, e);
		} finally {
			ReferenceCountUtil.release(msg);
		}
	}

	@Override
	public void channelReadComplete(final ChannelHandlerContext ctx) {
		if (dataBuf == null || dataBuf.size() < 1) {
			return;
		}
		MessageDispatch.dispatch(dataBuf.toByteArray(), ctx, rid);

		dataBuf = new ByteArrayOutputStream();
	}

	@Override
	public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
		logger.error("{} - ", rid, cause);
		ctx.close();
	}
}
