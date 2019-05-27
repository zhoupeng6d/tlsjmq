package org.zeromq.tlsjmq;

import org.zeromq.SocketType;
import org.zeromq.ZContext;
import org.zeromq.ZMQ;
import org.zeromq.ZMQ.Poller;
import org.zeromq.ZMQ.Socket;

import org.apache.log4j.Logger;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;


public class JMQChannel {
    private final Logger log = Logger.getLogger(getClass());

    public enum Mode {
        SERVER,
        CLIENT,
    }

    private ZMQ.Socket socket;
    private Mode       mode;

    public JMQChannel(ZMQ.Socket socket, Mode mode)
    {
        this.socket = socket;
        this.mode   = mode;
    }

    public String accept()
    {
        String id = "";
        String id_tmp;
        do {
            id_tmp = socket.recvStr(0);

                if (id_tmp.length() > 0) {
                    id = id_tmp;
                }

            socket.sendMore(id_tmp);
        } while(id_tmp.length() > 0);

        return id;
    }

    public int read(ByteBuffer dst)
    {
        return socket.recvByteBuffer(dst, 0);
    }

    public byte[] readb()
    {
        return socket.recv();
    }

    public int write(ByteBuffer src, boolean sendMore)
    {
        int ret = socket.sendByteBuffer(src, sendMore?zmq.ZMQ.ZMQ_SNDMORE:0);
        src.position(src.limit());
        return ret;
    }

    public void read0()
    {
        String data;
        log.debug("recv 0");
        data = socket.recvStr(0);
    }

    public void write0()
    {
        socket.send("");
    }
}