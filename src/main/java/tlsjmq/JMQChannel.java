package org.zeromq.tlsjmq;

import org.zeromq.SocketType;
import org.zeromq.ZContext;
import org.zeromq.ZMQ;
import org.zeromq.ZMQ.Poller;
import org.zeromq.ZMQ.Socket;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;


public class JMQChannel {
    public enum Mode {
        SERVER,
        CLIENT,
    }

    private ZMQ.Socket socket;
    private Mode       mode;
    private Boolean    bRead = false;
    private Boolean    bWrite = false;

    public JMQChannel(ZMQ.Socket socket, Mode mode)
    {
        this.socket = socket;
        this.mode   = mode;
    }

    public int read(ByteBuffer dst)
    {
        if (bRead)
        {
            socket.send("");
        }

        bWrite = false;
        bRead = true;
        return socket.recvByteBuffer(dst, 0);
    }

    public int write(ByteBuffer src)
    {
        if (bWrite)
        {
            String data;
            data = socket.recvStr(0);
        }
        bRead = false;
        bWrite = true;
        int ret = socket.sendByteBuffer(src, 0);
        src.position(src.limit());
        return ret;
    }

    public void close()
    {

    }
}