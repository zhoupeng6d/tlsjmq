package org.zeromq.tlsjmq;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.SecureRandom;

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

import org.apache.log4j.Logger;

import org.zeromq.tlsjmq.JMQChannel;
import org.zeromq.tlsjmq.TLSWrapper;

public class TLSClient {
    private final Logger log = Logger.getLogger(getClass());
    private ZContext     jmqContext;
    private JMQChannel   jmqChannel;
    private TLSWrapper   tlsWrapper;


    public TLSClient(String addr) throws IOException, Exception  {

        this.jmqContext = new ZContext();
        //System.out.println("I: connecting to server");
        Socket client = this.jmqContext.createSocket(SocketType.REQ);
        assert (client != null);
        client.setIdentity("client1".getBytes());
        client.connect(addr);

        this.jmqChannel = new JMQChannel(client, JMQChannel.Mode.CLIENT);

        tlsWrapper = new TLSWrapper("TLSv1.2",
                         TLSWrapper.createKeyManagers("./src/main/resources/client.jks", "123456", "123456"),
                         TLSWrapper.createTrustManagers("./src/main/resources/ca.jks", "123456"),
                         new SecureRandom(),
                         jmqChannel,
                         JMQChannel.Mode.CLIENT,
                         true);
    }

    public boolean connect() throws IOException {
        while (!tlsWrapper.isHandshakeDone())
        {
            if (!tlsWrapper.doHandshake())
            {
                log.debug("doHandshake false");
                return false;
            }
        }

        return true;
    }

    public void write(String message) throws IOException {
        tlsWrapper.write(message);
    }

    public String read() throws IOException {
        return tlsWrapper.read();
    }

    public void shutdown() throws IOException {
        log.debug("About to close connection with the server...");
        tlsWrapper.closeConnection();
        log.debug("Goodbye!");
    }

}
