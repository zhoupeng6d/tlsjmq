package org.zeromq.tlsjmq;

import org.junit.Test;
import static org.junit.Assert.*;

import java.io.IOException;

import org.zeromq.tlsjmq.TLSServer;
import org.zeromq.tlsjmq.RequestCallback;
import org.zeromq.tlsjmq.TLSWrapper;


/**
 * Unit test for simple App.
 */
public class AppTest {

	private Worker worker;
	private class Worker extends Thread
    {
		private TLSServer server;

		RequestCallback callback = new RequestCallback() {
            public String callback(String request)
            {
                try {
					System.out.printf("\033[32;4m" + ">>>>server recv: %s\r\n" + "\033[0m", request);

                    Thread.sleep(100);

					System.out.printf("\033[32;4m" + ">>>>server send: I am your server!\r\n" + "\033[0m");
					return "I am your server!";
				}
                catch(Exception e)
                {
                    System.out.println(e.toString());
                }

                return "";
            }
        };

		@Override
        public void run() {
			try {
				server = new TLSServer(TLSWrapper.createKeyManagers("./src/main/resources/server.jks", "123456", "123456"),
									   TLSWrapper.createTrustManagers("./src/main/resources/ca.jks", "123456"),
									   true,
									   "tcp://*:5556", callback);
				server.start();
			} catch (Exception e){
				e.printStackTrace();
			}
		}

		public void serverStop() {
			server.stop();
		}
	}

	public void serverRun() {
		worker = new Worker();
        worker.start();
	}

	public void serverStop() throws Exception {
		worker.serverStop();
		worker.sleep(2000);
	}

    /**
     * Rigorous Test.
     */
    @Test
    public void testApp() throws Exception {
		serverRun();

		Thread.sleep(1000);
		TLSClient client = new TLSClient(TLSWrapper.createKeyManagers("./src/main/resources/client.jks", "123456", "123456"),
										 TLSWrapper.createTrustManagers("./src/main/resources/ca.jks", "123456"),
									     "tcp://localhost:5556");
		if (client.connect())
		{
			client.write("Hello! I am a client!");
			System.out.printf("\033[31;4m" + ">>>>client send: Hello! I am a client\r\n" + "\033[0m");
			System.out.printf("\033[31;4m" + ">>>>client recv: %s\r\n" + "\033[0m", client.read());
			client.shutdown();
		}

		Thread.sleep(20000);

		serverStop();

        assertTrue(true);
    }
}
