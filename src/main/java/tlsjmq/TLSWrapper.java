package org.zeromq.tlsjmq;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.log4j.Logger;
import org.zeromq.tlsjmq.JMQChannel;
import org.zeromq.tlsjmq.JMQChannel.Mode;

public class TLSWrapper {

	private final Logger log = Logger.getLogger(getClass());

    /**
     * Will contain this peer's application data in plaintext, that will be later encrypted
     * using {@link SSLEngine#wrap(ByteBuffer, ByteBuffer)} and sent to the other peer. This buffer can typically
     * be of any size, as long as it is large enough to contain this peer's outgoing messages.
     * If this peer tries to send a message bigger than buffer's capacity a {@link BufferOverflowException}
     * will be thrown.
     */
    private ByteBuffer myAppData;

    /**
     * Will contain this peer's encrypted data, that will be generated after {@link SSLEngine#wrap(ByteBuffer, ByteBuffer)}
     * is applied on {@link TLSWrapper#myAppData}. It should be initialized using {@link SSLSession#getPacketBufferSize()},
     * which returns the size up to which, SSL/TLS packets will be generated from the engine under a session.
     * All SSLEngine network buffers should be sized at least this large to avoid insufficient space problems when performing wrap and unwrap calls.
     */
    private ByteBuffer myNetData;

    /**
     * Will contain the other peer's (decrypted) application data. It must be large enough to hold the application data
     * from any peer. Can be initialized with {@link SSLSession#getApplicationBufferSize()} for an estimation
     * of the other peer's application data and should be enlarged if this size is not enough.
     */
    private ByteBuffer peerAppData;

    /**
     * Will contain the other peer's encrypted data. The SSL/TLS protocols specify that implementations should produce packets containing at most 16 KB of plaintext,
     * so a buffer sized to this value should normally cause no capacity problems. However, some implementations violate the specification and generate large records up to 32 KB.
     * If the {@link SSLEngine#unwrap(ByteBuffer, ByteBuffer)} detects large inbound packets, the buffer sizes returned by SSLSession will be updated dynamically, so the this peer
     * should check for overflow conditions and enlarge the buffer using the session's (updated) buffer size.
     */
    private ByteBuffer peerNetData;

    /**
     * Will be used to execute tasks that may emerge during handshake in parallel with the server's main thread.
     */
    private ExecutorService executor = Executors.newSingleThreadExecutor();

    public    enum TLSStatus {
        HANDSHAKING,
        CONNECTED,
        CLOSED,
        ERROR,
    }

    private SSLEngine       engine;
    private JMQChannel      jmqChannel;
    private JMQChannel.Mode tlsMode;
    private HandshakeStatus handshakeStatus;
    public  TLSStatus       tlsStatus = TLSStatus.HANDSHAKING;

    private int readcnt = 0;
    private int writecnt = 0;


    public TLSWrapper(String protocol, javax.net.ssl.KeyManager[] km, javax.net.ssl.TrustManager[] tm, java.security.SecureRandom random,
                     JMQChannel jmqChannel, JMQChannel.Mode mode, boolean needClientAuth) throws IOException, Exception
    {
        this.jmqChannel = jmqChannel;
        this.tlsMode    = mode;

        if (JMQChannel.Mode.SERVER == mode)
        {
            SSLContext context = SSLContext.getInstance(protocol);
            context.init(km, tm, random);

            SSLSession dummySession = context.createSSLEngine().getSession();
            myAppData = ByteBuffer.allocate(dummySession.getApplicationBufferSize());
            myNetData = ByteBuffer.allocate(dummySession.getPacketBufferSize());
            peerAppData = ByteBuffer.allocate(dummySession.getApplicationBufferSize());
            peerNetData = ByteBuffer.allocate(dummySession.getPacketBufferSize());
            dummySession.invalidate();

            engine = context.createSSLEngine();
            engine.setUseClientMode(false);
            engine.setNeedClientAuth(needClientAuth);
            engine.beginHandshake();
        }
        else if (JMQChannel.Mode.CLIENT == mode)
        {
            SSLContext context = SSLContext.getInstance(protocol);
            context.init(km, tm, random);
            engine = context.createSSLEngine();
            engine.setUseClientMode(true);
            engine.beginHandshake();

            SSLSession session = engine.getSession();
            myAppData = ByteBuffer.allocate(1024);
            myNetData = ByteBuffer.allocate(session.getPacketBufferSize());
            peerAppData = ByteBuffer.allocate(1024);
            peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
        }

        handshakeStatus = engine.getHandshakeStatus();
    }

    public String read() throws IOException
    {
        log.debug(tlsMode+": "+"About to read from a " + tlsMode + "...");

        peerNetData.clear();
        byte[] recvNetData = jmqChannel.readb();
        readcnt = 1;
        writecnt = 0;
        if (recvNetData.length > 0)
        {
            peerNetData = ByteBuffer.allocate(recvNetData.length);
        }

        peerNetData.put(recvNetData);
        log.debug(tlsMode+": "+"read:" + peerNetData.position());

        int bytesRead = recvNetData.length;
        log.debug(tlsMode+": "+"read size:"+bytesRead);
        if (bytesRead > 0) {
            peerNetData.flip();
            while (peerNetData.hasRemaining()) {
                peerAppData.clear();
                SSLEngineResult result = engine.unwrap(peerNetData, peerAppData);
                switch (result.getStatus()) {
                case OK:
                    peerAppData.flip();
                    return new String(peerAppData.array());
                case BUFFER_OVERFLOW:
                    peerAppData = enlargeApplicationBuffer(engine, peerAppData);
                    break;
                case BUFFER_UNDERFLOW:
                    peerNetData = handleBufferUnderflow(engine, peerNetData);
                    break;
                case CLOSED:
                    log.debug(tlsMode+": "+"Client wants to close connection...");
                    closeConnection();
                    tlsStatus = TLSStatus.CLOSED;
                    return null;
                default:
                    throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                }
            }
        } else if (bytesRead < 0) {
            log.error(tlsMode + ": " + "Received end of stream. Will try to close connection with client...");
            handleEndOfStream();
            log.debug(tlsMode+": "+"Goodbye client!");
        } else if (bytesRead == 0) {
            log.debug(tlsMode+": "+ "write0");
            return "";
        }

        return null;
    }

    public void write(String message) throws IOException
    {
        log.debug(tlsMode+": "+"About to write to a client...");

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
                    log.debug(tlsMode+": "+"send:" + myNetData.remaining());
                    jmqChannel.write(myNetData, false);
                    readcnt = 0;
                    writecnt = 1;
                }
                log.debug(tlsMode+": "+"Message sent to the client: " + message);
                break;
            case BUFFER_OVERFLOW:
                myNetData = enlargePacketBuffer(engine, myNetData);
                break;
            case BUFFER_UNDERFLOW:
                throw new SSLException("Buffer underflow occured after a wrap. I don't think we should ever get here.");
            case CLOSED:
                closeConnection();
                return;
            default:
                throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
            }
        }
    }


    public boolean isHandshakeDone()
    {
        log.debug(tlsMode+": "+"handshakestatus:"+engine.getHandshakeStatus());
        return (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) || (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING);
    }

    private boolean handshakeUnwrap() throws IOException
    {
        SSLEngineResult result;
        do {
            log.debug(tlsMode+": "+"handshakestatus:"+engine.getHandshakeStatus());
            try {
                result = engine.unwrap(peerNetData, peerAppData);
                if (!peerNetData.hasRemaining())
                    peerNetData.position(peerNetData.limit());
                handshakeStatus = result.getHandshakeStatus();
            } catch (SSLException sslException) {
                log.error(tlsMode + ": " + "A problem was encountered while processing the data that caused the SSLEngine to abort. Will try to properly close connection...");
                engine.closeOutbound();
                handshakeStatus = engine.getHandshakeStatus();
                //break;
                return false;
            }
            log.debug(tlsMode+": "+"unwrap status:"+result.getStatus());
            switch (result.getStatus()) {
                case OK:
                break;
                case BUFFER_OVERFLOW:
                // Will occur when peerAppData's capacity is smaller than the data derived from peerNetData's unwrap.
                peerAppData = enlargeApplicationBuffer(engine, peerAppData);
                return handshakeUnwrap();
                //break;
                case BUFFER_UNDERFLOW:
                // Will occur either when no data was read from the peer or when the peerNetData buffer was too small to hold all peer's data.
                peerNetData = handleBufferUnderflow(engine, peerNetData);
                return handshakeUnwrap();
                //break;
                case CLOSED:
                tlsStatus = TLSStatus.CLOSED;
                if (engine.isOutboundDone()) {
                    return false;
                } else {
                    engine.closeOutbound();
                    handshakeStatus = engine.getHandshakeStatus();
                    break;
                }
                default:
                throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
            }

            while (HandshakeStatus.NEED_TASK == handshakeStatus)
            {
                handshakeTask();
            }

            log.debug(tlsMode + ": " + "peerNetData remaining:" + peerNetData.remaining() + " position:"+ peerNetData.position());
        } while (peerNetData.hasRemaining());

        return true;
    }

    private boolean handshakeWrap() throws IOException
    {
        SSLEngineResult result;
        try {
            result = engine.wrap(myAppData, myNetData);
            handshakeStatus = result.getHandshakeStatus();
        } catch (SSLException sslException) {
            log.error(tlsMode + ": " + "A problem was encountered while processing the data that caused the SSLEngine to abort. Will try to properly close connection...");
            engine.closeOutbound();
            handshakeStatus = engine.getHandshakeStatus();
            log.debug(sslException.getMessage());
            //break;
            return false;
        }
        log.debug(tlsMode+": "+"wrap status:"+result.getStatus());
        switch (result.getStatus()) {
            case OK :
                myNetData.flip();
                while (myNetData.hasRemaining()) {
                    log.debug(tlsMode+": "+"write1:" + myNetData.remaining());
                    jmqChannel.write(myNetData, false);
                }
                break;
            case BUFFER_OVERFLOW:
                // Will occur if there is not enough space in myNetData buffer to write all the data that would be generated by the method wrap.
                // Since myNetData is set to session's packet size we should not get to this point because SSLEngine is supposed
                // to produce messages smaller or equal to that, but a general handling would be the following:
                myNetData = enlargePacketBuffer(engine, myNetData);
                return handshakeWrap();
                //break;
            case BUFFER_UNDERFLOW:
                throw new SSLException("Buffer underflow occured after a wrap. I don't think we should ever get here.");
            case CLOSED:
                try {
                    myNetData.flip();
                    while (myNetData.hasRemaining()) {
                        log.debug(tlsMode+": "+"write2:" + myNetData.remaining());
                        jmqChannel.write(myNetData, false);
                    }
                    // At this point the handshake status will probably be NEED_UNWRAP so we make sure that peerNetData is clear to read.
                    peerNetData.clear();
                } catch (Exception e) {
                    log.error(tlsMode + ": " + "Failed to send server's CLOSE message due to socket channel's failure.");
                    handshakeStatus = engine.getHandshakeStatus();
                }
                break;
            default:
                throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
        }

        return true;
    }

    private void handshakeTask()
    {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            executor.execute(task);
        }
        handshakeStatus = engine.getHandshakeStatus();
    }

    /*
    *      client          server          message
    *      ======          ======          =======
    *      wrap()          ...             ClientHello
    *      ...             unwrap()        ClientHello
    *      ...             wrap()          ServerHello/Certificate
    *      unwrap()        ...             ServerHello/Certificate
    *      wrap()          ...             ClientKeyExchange
    *      wrap()          ...             ChangeCipherSpec
    *      wrap()          ...             Finished
    *      ...             unwrap()        ClientKeyExchange
    *      ...             unwrap()        ChangeCipherSpec
    *      ...             unwrap()        Finished
    *      ...             wrap()          ChangeCipherSpec
    *      ...             wrap()          Finished
    *      unwrap()        ...             ChangeCipherSpec
    *      unwrap()        ...             Finished
    */
    public boolean doHandshake() throws IOException {

        log.debug(tlsMode+": "+"About to do handshake...");

        SSLEngineResult result;

        // TLSWrapper's fields myAppData and peerAppData are supposed to be large enough to hold all message data the peer
        // will send and expects to receive from the other peer respectively. Since the messages to be exchanged will usually be less
        // than 16KB long the capacity of these fields should also be smaller. Here we initialize these two local buffers
        // to be used for the handshake, while keeping client's buffers at the same size.
        int appBufferSize = engine.getSession().getApplicationBufferSize();
        ByteBuffer myAppData = ByteBuffer.allocate(appBufferSize);
        ByteBuffer peerAppData = ByteBuffer.allocate(appBufferSize);
        myNetData.clear();
        peerNetData.clear();

        handshakeStatus = engine.getHandshakeStatus();
        log.debug(tlsMode + ": " + "status:" + handshakeStatus);
        if (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED && handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            if (HandshakeStatus.NEED_UNWRAP == handshakeStatus)
            {
                log.debug(tlsMode+": "+">>>>unwrap");
                if (((tlsMode == JMQChannel.Mode.CLIENT) && (readcnt != 0))
                    || ((tlsMode == JMQChannel.Mode.CLIENT) && (writecnt != 1)))
                {
                    jmqChannel.write0();
                    writecnt = 0;
                    readcnt = 0;
                }
                byte[] recvNetData = jmqChannel.readb();
                readcnt = 1;
                writecnt = 0;
                if (recvNetData.length >= 0)
                {
                    peerNetData = ByteBuffer.allocate(recvNetData.length);
                }

                peerNetData.put(recvNetData);
                log.debug(tlsMode+": "+"read:" + peerNetData.position());
                peerNetData.flip();
                if (!handshakeUnwrap()) return false;
            }

            log.debug(tlsMode+": "+"status:" + handshakeStatus);

            if (HandshakeStatus.NEED_WRAP == handshakeStatus)
            {
                log.debug(tlsMode+": "+">>>>wrap");

                if ((tlsMode == JMQChannel.Mode.SERVER) && (readcnt != 1))
                {
                    jmqChannel.read0();
                    writecnt = 0;
                    readcnt = 0;
                }

                if ((tlsMode == JMQChannel.Mode.CLIENT) && (writecnt != 0))
                {
                    jmqChannel.read0();
                    writecnt = 0;
                    readcnt = 0;
                }

                myNetData.clear();
                if (!handshakeWrap()) return false;

                writecnt = 1;
                readcnt  = 0;
            }

            log.debug(tlsMode+": "+"status:" + handshakeStatus);

            if (HandshakeStatus.FINISHED == handshakeStatus)
            {
                tlsStatus = TLSStatus.CONNECTED;

                writecnt = 0;
                readcnt  = 0;
            }
            if (HandshakeStatus.NOT_HANDSHAKING == handshakeStatus)
            {

            }

            if (tlsMode == JMQChannel.Mode.SERVER)
            {
                if (readcnt != 0)
                {
                    jmqChannel.write0();
                    readcnt = 0;
                }
                if (writecnt != 0) writecnt = 0;
            }
        }

        return true;
    }

    private ByteBuffer enlargePacketBuffer(SSLEngine engine, ByteBuffer buffer) {
        return enlargeBuffer(buffer, engine.getSession().getPacketBufferSize());
    }

    private ByteBuffer enlargeApplicationBuffer(SSLEngine engine, ByteBuffer buffer) {
        return enlargeBuffer(buffer, engine.getSession().getApplicationBufferSize());
    }

    /**
     * Compares <code>sessionProposedCapacity<code> with buffer's capacity. If buffer's capacity is smaller,
     * returns a buffer with the proposed capacity. If it's equal or larger, returns a buffer
     * with capacity twice the size of the initial one.
     *
     * @param buffer - the buffer to be enlarged.
     * @param sessionProposedCapacity - the minimum size of the new buffer, proposed by {@link SSLSession}.
     * @return A new buffer with a larger capacity.
     */
    protected ByteBuffer enlargeBuffer(ByteBuffer buffer, int sessionProposedCapacity) {
        if (sessionProposedCapacity > buffer.capacity()) {
            buffer = ByteBuffer.allocate(sessionProposedCapacity);
            log.debug("buffer size:"+sessionProposedCapacity);
        } else {
            buffer = ByteBuffer.allocate(buffer.capacity() * 2);
            log.debug("buffer size:"+buffer.capacity() * 2);
        }
        return buffer;
    }

    /**
     * Handles {@link SSLEngineResult.TLSStatus#BUFFER_UNDERFLOW}. Will check if the buffer is already filled, and if there is no space problem
     * will return the same buffer, so the client tries to read again. If the buffer is already filled will try to enlarge the buffer either to
     * session's proposed size or to a larger capacity. A buffer underflow can happen only after an unwrap, so the buffer will always be a
     * peerNetData buffer.
     *
     * @param buffer - will always be peerNetData buffer.
     * @param engine - the engine used for encryption/decryption of the data exchanged between the two peers.
     * @return The same buffer if there is no space problem or a new buffer with the same data but more space.
     * @throws Exception
     */
    private ByteBuffer handleBufferUnderflow(SSLEngine engine, ByteBuffer buffer) {
        if (engine.getSession().getPacketBufferSize() < buffer.limit()) {
            return buffer;
        } else {
            ByteBuffer replaceBuffer = enlargePacketBuffer(engine, buffer);
            buffer.flip();
            replaceBuffer.put(buffer);
            return replaceBuffer;
        }
    }

    /**
     * This method should be called when this peer wants to explicitly close the connection
     * or when a close message has arrived from the other peer, in order to provide an orderly shutdown.
     * <p/>
     * It first calls {@link SSLEngine#closeOutbound()} which prepares this peer to send its own close message and
     * sets {@link SSLEngine} to the <code>NEED_WRAP</code> state. Then, it delegates the exchange of close messages
     * to the handshake method and finally, it closes socket channel.
     *
     * @param jmqChannel - the transport link used between the two peers.
     * @param engine - the engine used for encryption/decryption of the data exchanged between the two peers.
     * @throws IOException if an I/O error occurs to the socket channel.
     */
    public void closeConnection() throws IOException  {
        engine.closeOutbound();
        doHandshake();
        executor.shutdown();
    }

    /**
     * In addition to orderly shutdowns, an unorderly shutdown may occur, when the transport link (socket channel)
     * is severed before close messages are exchanged. This may happen by getting an -1 or {@link IOException}
     * when trying to read from the socket channel, or an {@link IOException} when trying to write to it.
     * In both cases {@link SSLEngine#closeInbound()} should be called and then try to follow the standard procedure.
     *
     * @param jmqChannel - the transport link used between the two peers.
     * @param engine - the engine used for encryption/decryption of the data exchanged between the two peers.
     * @throws IOException if an I/O error occurs to the socket channel.
     */
    private void handleEndOfStream() throws IOException  {
        try {
            engine.closeInbound();
        } catch (Exception e) {
            log.error(tlsMode + ": " + "This engine was forced to close inbound, without having received the proper SSL/TLS close notification message from the peer, due to end of stream.");
        }
        closeConnection();
    }

    /**
     * Creates the key managers required to initiate the {@link SSLContext}, using a JKS keystore as an input.
     *
     * @param filepath - the path to the JKS keystore.
     * @param keystorePassword - the keystore's password.
     * @param keyPassword - the key's passsword.
     * @return {@link KeyManager} array that will be used to initiate the {@link SSLContext}.
     * @throws Exception
     */
    public static KeyManager[] createKeyManagers(String filepath, String keystorePassword, String keyPassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        InputStream keyStoreIS = new FileInputStream(filepath);
        try {
            keyStore.load(keyStoreIS, keystorePassword.toCharArray());
        } finally {
            if (keyStoreIS != null) {
                keyStoreIS.close();
            }
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyPassword.toCharArray());
        return kmf.getKeyManagers();
    }

    /**
     * Creates the trust managers required to initiate the {@link SSLContext}, using a JKS keystore as an input.
     *
     * @param filepath - the path to the JKS keystore.
     * @param keystorePassword - the keystore's password.
     * @return {@link TrustManager} array, that will be used to initiate the {@link SSLContext}.
     * @throws Exception
     */
    public static TrustManager[] createTrustManagers(String filepath, String keystorePassword) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        InputStream trustStoreIS = new FileInputStream(filepath);
        try {
            trustStore.load(trustStoreIS, keystorePassword.toCharArray());
        } finally {
            if (trustStoreIS != null) {
                trustStoreIS.close();
            }
        }
        TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trustStore);
        return trustFactory.getTrustManagers();
    }
}
