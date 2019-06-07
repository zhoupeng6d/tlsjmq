package org.zeromq.tlsjmq;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.SecureRandom;
import java.util.Iterator;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import org.zeromq.SocketType;
import org.zeromq.ZContext;
import org.zeromq.ZMQ;
import org.zeromq.ZMQ.Poller;
import org.zeromq.ZMQ.Socket;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;

import org.zeromq.tlsjmq.JMQChannel;
import org.zeromq.tlsjmq.TLSWrapper;
import org.zeromq.tlsjmq.RequestCallback;

public class TLSServer {

    private final Logger    log = Logger.getLogger(getClass());
	private boolean         active;
    private ZContext        jmqContext;
    private JMQChannel      jmqChannel;
    private RequestCallback requestCallback;
    private javax.net.ssl.KeyManager[] km;
    private javax.net.ssl.TrustManager[] tm;


    public TLSServer(javax.net.ssl.KeyManager[] km, javax.net.ssl.TrustManager[] tm, String addr, RequestCallback requestCallback) throws IOException {

        this.km = km;
        this.tm = tm;

        this.requestCallback = requestCallback;

        jmqContext = new ZContext();
        ZMQ.Socket socket = jmqContext.createSocket(SocketType.ROUTER);
        socket.bind(addr);

        jmqChannel = new JMQChannel(socket, JMQChannel.Mode.SERVER);

        active = true;
    }

    public void start() throws IOException, Exception {

        log.debug("Initialized and waiting for new connections...");
        TLSWrapper tlsWrapper;
        Map<String, TLSWrapper> clientMap = new HashMap<String, TLSWrapper>();

        int cnt = 0;
        while (isActive())
        {
            String key = this.jmqChannel.accept();

            log.debug("client id:" + key);

            if (clientMap.containsKey(key))
            {
                log.debug("clientMap get");
                tlsWrapper = clientMap.get(key);
            }
            else
            {
                log.debug("clientMap new");
                tlsWrapper = new TLSWrapper("TLSv1.2",
                                    km,
                                    tm,
                                    new SecureRandom(),
                                    jmqChannel,
                                    JMQChannel.Mode.SERVER,
                                    true);
                clientMap.put(key, tlsWrapper);
            }

            if (!tlsWrapper.isHandshakeDone())
            {
                tlsWrapper.doHandshake();
                continue;
            }

            String request = tlsWrapper.read();

            if (request != null)
            {
                String response = requestCallback.callback(request);

                tlsWrapper.write(response);
            }

            if (tlsWrapper.tlsStatus != TLSWrapper.TLSStatus.CONNECTED)
            {
                log.debug("clientMap remove");
                clientMap.remove(key);
            }
        }

        log.debug("Goodbye!");
    }

    public void stop() {
    	active = false;
    }

    private boolean isActive() {
        return active;
    }
}
