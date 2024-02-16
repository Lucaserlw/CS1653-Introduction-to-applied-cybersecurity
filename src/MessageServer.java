import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/*
 * Creates threads for incoming connections
 * Maintains channel list
 * Helper classes save channel list to ChannelList.bin every 5 minutes or on shutdown
 * Also creates messages folder if it does not exist already
 */

public class MessageServer extends Server {
	
	public static final int SERVER_PORT = 4321;
	public static ChannelList channelList;
	public static String privateKeyFile = "HostPrivate.bin";
	public static String publicKeyFile = "HostPublic.bin";
	public static String masterKeyFile = "HostMaster.bin";
	public static int bBits = 20;
	
	public ServerSocket serverSock;
	public static PublicKey publicKey = null;
	public static PrivateKey privateKey = null;
	public static SecretKey masterKey = null;

	public static CryptoSuite suite;
	
	public MessageServer() {
		super(SERVER_PORT, "MessageServer");
	}

	public MessageServer(int _port) {
		super(_port, "MessageServer");
	}
	
	public void start() {
		loadKeys();
		String listFile = "ChannelList.bin";
		ObjectInputStream fileStream;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerChannels());
		runtime.addShutdownHook(catchExit);
		
		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(listFile);
			fileStream = new ObjectInputStream(fis);
			channelList = (ChannelList)fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("ChannelList does not exist. Creating ChannelList...");
			
			channelList = new ChannelList();
			
		}
		catch(IOException e)
		{
			System.out.println("Error reading from ChannelList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from ChannelList file");
			System.exit(-1);
		}
		
		File file = new File("messages");
		 if (file.mkdir()) {
			 System.out.println("Created new messages directory");
		 }
		 else if (file.exists()){
			 System.out.println("Found messages directory");
		 }
		 else {
			 System.out.println("Error creating messages directory");				 
		 }
		
		String fingerprint = suite.getFingerprint(publicKey);
		System.out.printf("Message Server Fingerprint: %s\n", fingerprint);

		// Autosave Daemon. Saves lists every 5 minutes
		AutoSaveChannels aSave = new AutoSaveChannels();
		aSave.setDaemon(true);
		aSave.start();
		
		
		boolean running = true;
		
		try
		{			
			serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
			
			Socket sock = null;
			Thread thread = null;
			
			while(running)
			{
				sock = serverSock.accept();
				thread = new MessageThread(sock);
				thread.start();
			}
			
			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	private static void loadKeys() {
		try {
			FileInputStream publicF = new FileInputStream(publicKeyFile);
			ObjectInputStream publicStream = new ObjectInputStream(publicF);
			publicKey = (PublicKey) publicStream.readObject();
			publicStream.close();
			FileInputStream privateF = new FileInputStream(privateKeyFile);
			ObjectInputStream privateStream = new ObjectInputStream(privateF);
			privateKey = (PrivateKey) privateStream.readObject();
			privateStream.close();
			FileInputStream masterF = new FileInputStream(masterKeyFile);
			ObjectInputStream masterStream = new ObjectInputStream(masterF);
			masterKey = (SecretKey) masterStream.readObject();
			masterStream.close();
		} catch (FileNotFoundException e) {
			System.out.println("Failed to fetch public and private keys. Generating new key pair...");
			try {
				KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(2048);
				KeyPair kp = kpg.generateKeyPair();
				publicKey = kp.getPublic();
				privateKey = kp.getPrivate();
				ObjectOutputStream publicOut = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
				publicOut.writeObject(publicKey);
				publicOut.close();
				ObjectOutputStream privateOut = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
				privateOut.writeObject(privateKey);
				privateOut.close();
				KeyGenerator kg = KeyGenerator.getInstance("AES");
				kg.init(256);
				masterKey = kg.generateKey();
				ObjectOutputStream masterOut = new ObjectOutputStream(new FileOutputStream(masterKeyFile));
				masterOut.writeObject(masterKey);
				masterOut.close();
			} catch (NoSuchAlgorithmException ex) {
				System.out.println("Could not get KeyPairGenerator for RSA algorithm");
				System.exit(-1);
			} catch (IOException ex) {
				System.out.println("Failed to save public and private keys to file");
				System.exit(-1);
			}
		} catch (IOException e) {
			System.out.println("Error reading from key pair files");
			System.exit(-1);
		} catch (ClassNotFoundException e) {
			System.out.println("Error reading from key pair files");
			System.exit(-1);
		}
		suite = new CryptoSuite(publicKey, privateKey);
	}
}

//This thread saves user and group lists
class ShutDownListenerChannels implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("ChannelList.bin"));
			outStream.writeObject(MessageServer.channelList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveChannels extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("ChannelList.bin"));
					outStream.writeObject(MessageServer.channelList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		} while(true);
	}
}

