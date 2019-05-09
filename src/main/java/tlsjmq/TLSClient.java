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

import org.zeromq.tlsjmq.JMQChannel;

/**
 * An SSL/TLS client that connects to a server using its IP address and port.
 * <p/>
 * After initialization of a {@link TLSClient} object, {@link TLSClient#connect()} should be called,
 * in order to establish connection with the server.
 * <p/>
 * When the connection between the client and the object is established, {@link TLSClient} provides
 * a public write and read method, in order to communicate with its peer.
 *
 * @author <a href="mailto:alex.a.karnezis@gmail.com">Alex Karnezis</a>
 */
public class TLSClient extends TLSWrapper {

    /**
     * The remote address of the server this client is configured to connect to.
     */
	private String addr;

	/**
	 * The engine that will be used to encrypt/decrypt data between this client and the server.
	 */
    private SSLEngine engine;

    /**
     * The socket channel that will be used as the transport link between this client and the server.
     */
    //private SocketChannel socketChannel;

    private ZContext   jmqContext;
    private JMQChannel jmqChannel;


    /**
     * Initiates the engine to run as a client using peer information, and allocates space for the
     * buffers that will be used by the engine.
     *
     * @param protocol The SSL/TLS protocol to be used. Java 1.6 will only run with up to TLSv1 protocol. Java 1.7 or higher also supports TLSv1.1 and TLSv1.2 protocols.
     * @param remoteAddress The IP address of the peer.
     * @param port The peer's port that will be used.
     * @throws Exception
     */
    public TLSClient(String protocol, String addr) throws Exception  {

        this.addr = addr;

        SSLContext context = SSLContext.getInstance(protocol);
        context.init(createKeyManagers("./src/main/resources/client.jks", "123456", "123456"), createTrustManagers("./src/main/resources/ca.jks", "123456"), new SecureRandom());
        //context.init(null, createTrustManagers("./src/main/resources/ca.jks", "123456"), new SecureRandom());
        engine = context.createSSLEngine();
        engine.setUseClientMode(true);

        SSLSession session = engine.getSession();
        myAppData = ByteBuffer.allocate(1024);
        myNetData = ByteBuffer.allocate(session.getPacketBufferSize());
        peerAppData = ByteBuffer.allocate(1024);
        peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
    }

    /**
     * Opens a socket channel to communicate with the configured server and tries to complete the handshake protocol.
     *
     * @return True if client established a connection with the server, false otherwise.
     * @throws Exception
     */
    public boolean connect() throws Exception {

        this.jmqContext = new ZContext();
        //System.out.println("I: connecting to server");
        Socket client = this.jmqContext.createSocket(SocketType.REQ);
        assert (client != null);
        client.connect(this.addr);

        this.jmqChannel = new JMQChannel(client, JMQChannel.Mode.CLIENT);

    	engine.beginHandshake();
    	return doHandshake(this.jmqChannel, engine);
    }

    /**
     * Public method to send a message to the server.
     *
     * @param message - message to be sent to the server.
     * @throws IOException if an I/O error occurs to the socket channel.
     */
    public void write(String message) throws IOException {
        write(this.jmqChannel, engine, message);
    }

    /**
     * Implements the write method that sends a message to the server the client is connected to,
     * but should not be called by the user, since socket channel and engine are inner class' variables.
     * {@link TLSClient#write(String)} should be called instead.
     *
     * @param message - message to be sent to the server.
     * @param engine - the engine used for encryption/decryption of the data exchanged between the two peers.
     * @throws IOException if an I/O error occurs to the socket channel.
     */
    @Override
    protected void write(JMQChannel jmqChannel, SSLEngine engine, String message) throws IOException {

        log.debug("About to write to the server...");

        myAppData.clear();
        myAppData.put(message.getBytes());
        myAppData.flip();
        while (myAppData.hasRemaining()) {
            // The loop has a meaning for (outgoing) messages larger than 16KB.
            // Every wrap call will remove 16KB from the original message and send it to the remote peer.
            myNetData.clear();
            SSLEngineResult result = engine.wrap(myAppData, myNetData);
            switch (result.getStatus()) {
            case OK:
                myNetData.flip();
                while (myNetData.hasRemaining()) {
                    jmqChannel.write(myNetData);
                }
                log.debug("Message sent to the server: " + message);
                break;
            case BUFFER_OVERFLOW:
                myNetData = enlargePacketBuffer(engine, myNetData);
                break;
            case BUFFER_UNDERFLOW:
                throw new SSLException("Buffer underflow occured after a wrap. I don't think we should ever get here.");
            case CLOSED:
                closeConnection(jmqChannel, engine);
                return;
            default:
                throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
            }
        }

    }

    /**
     * Public method to try to read from the server.
     *
     * @throws Exception
     */
    public void read() throws Exception {
        read(this.jmqChannel, engine);
    }

    /**
     * Will wait for response from the remote peer, until it actually gets something.
     * Uses {@link SocketChannel#read(ByteBuffer)}, which is non-blocking, and if
     * it gets nothing from the peer, waits for {@code waitToReadMillis} and tries again.
     * <p/>
     * Just like {@link TLSClient#read(SocketChannel, SSLEngine)} it uses inner class' socket channel
     * and engine and should not be used by the client. {@link TLSClient#read()} should be called instead.
     *
     * @param message - message to be sent to the server.
     * @param engine - the engine used for encryption/decryption of the data exchanged between the two peers.
     * @throws Exception
     */
    @Override
    protected void read(JMQChannel jmqChannel, SSLEngine engine) throws Exception  {

        log.debug("About to read from the server...");

        peerNetData.clear();
        int waitToReadMillis = 50;
        boolean exitReadLoop = false;
        while (!exitReadLoop) {
            int bytesRead = jmqChannel.read(peerNetData);
            if (bytesRead > 0) {
                peerNetData.flip();
                while (peerNetData.hasRemaining()) {
                    peerAppData.clear();
                    SSLEngineResult result = engine.unwrap(peerNetData, peerAppData);
                    switch (result.getStatus()) {
                    case OK:
                        peerAppData.flip();
                        log.debug("Server response: " + new String(peerAppData.array()));
                        exitReadLoop = true;
                        break;
                    case BUFFER_OVERFLOW:
                        peerAppData = enlargeApplicationBuffer(engine, peerAppData);
                        break;
                    case BUFFER_UNDERFLOW:
                        peerNetData = handleBufferUnderflow(engine, peerNetData);
                        break;
                    case CLOSED:
                        closeConnection(jmqChannel, engine);
                        return;
                    default:
                        throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                    }
                }
            } else if (bytesRead < 0) {
                handleEndOfStream(jmqChannel, engine);
                return;
            }
            Thread.sleep(waitToReadMillis);
        }
    }

    /**
     * Should be called when the client wants to explicitly close the connection to the server.
     *
     * @throws IOException if an I/O error occurs to the socket channel.
     */
    public void shutdown() throws IOException {
        log.debug("About to close connection with the server...");
        closeConnection(jmqChannel, engine);
        executor.shutdown();
        log.debug("Goodbye!");
    }

}
