package org.zeromq.tlsjmq;

import org.junit.Test;

import static org.junit.Assert.*;

import org.zeromq.tlsjmq.TLSServer;


/**
 * Unit test for simple App.
 */
public class AppTest {

    private TLSServer server;

	public void serverRun() {
		try {
			server = new TLSServer("TLSv1.2", "tcp://*:5556");
			server.start();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Should be called in order to gracefully stop the server.
	 */
	public void serverStop() {
		server.stop();
    }

    /**
     * Rigorous Test.
     */
    @Test
    public void testApp() throws Exception {
		serverRun();

		TLSClient client = new TLSClient("TLSv1.2", "tcp://localhost:5556");
		client.connect();
		client.write("Hello! I am a client!");
		client.read();
		client.shutdown();

		serverStop();

        assertTrue(true);
    }
}
