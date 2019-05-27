package org.zeromq.tlsjmq;

public interface RequestCallback {
    String callback(String request);
}