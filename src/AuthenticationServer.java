/* Authentication server. Server loads the users and groups from UserList.bin and GroupList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator
 * and the owner of the ADMIN group.
 * If group list does not exist, it creates a new list and adds the ADMIN group.
 * On exit, the server saves the user and group lists to file. 
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;

import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;

public class AuthenticationServer extends Server {

	public static final int SERVER_PORT = 8765;
	public static String userFile = "UserList.bin";
	public static String groupFile = "GroupList.bin";
	public static String privateKeyFile = "AuthPrivate.bin";
	public static String publicKeyFile = "AuthPublic.bin";
	public static String masterKeyFile = "AuthMaster.bin";

	public PublicKey publicKey = null;
	public PrivateKey privateKey = null;
	public SecretKey masterKey = null;
	public CryptoSuite suite = null;

	public ServerSocket serverSock;
	public UserList userList;
	public GroupList groupList;

	public AuthenticationServer() {
		super(SERVER_PORT, "ALPHA");
	}

	public AuthenticationServer(int _port) {
		super(_port, "ALPHA");
	}

	public void start() {
		loadKeys();

		// Overwrote server.start() because if no user file exists, initial admin
		// account needs to be created
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

		// This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		// Open user file to get user list
		try {
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList) userStream.readObject();
		} catch (FileNotFoundException e) {
			System.out.println("UserList file does not exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
			System.out.print("Enter your password: ");
			String password = console.next();
			byte[] salt = suite.generateSalt();
			SecretKey uk = suite.computeKey(password, salt);

			// Create a new list, add current user to the ADMIN group. They now own the
			// ADMIN group.
			userList = new UserList();
			userList.addUser(username, uk, salt);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
		} catch (IOException e) {
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		} catch (ClassNotFoundException e) {
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		// Open group file to get group list
		try {
			FileInputStream fis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis);
			groupList = (GroupList) groupStream.readObject();
		} catch (FileNotFoundException e) {
			System.out.println("GroupList File Does Not Exist. Creating GroupList...");
			System.out.println("No groups currently exist. Adding you to the ADMIN group.");

			String username;
			boolean error;
			// This loop tests that the username entered exists
			do {
				error = true;
				System.out.print("Enter your username: ");
				username = console.next();

				if (userList.checkUser(username)) {
					error = false;
				} else {
					System.out.println("That username does not exist");
				}
			} while (error);

			groupList = new GroupList();
			SecretKey gk = suite.generateKey();
			groupList.addGroup(username, "ADMIN", gk);
		} catch (IOException e) {
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		} catch (ClassNotFoundException e) {
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		console.close();
		System.out.println("Welcome to the Authentication Server\nServer online");

		// Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		// This block listens for connections and creates threads on new connections
		try {

			serverSock = new ServerSocket(port);

			Socket sock = null;
			AuthenticationThread thread = null;

			while (true) {
				sock = serverSock.accept();
				thread = new AuthenticationThread(sock, this);
				thread.start();
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}

	private void loadKeys() {
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

// This thread saves user and group lists
class ShutDownListener extends Thread {
	public AuthenticationServer my_gs;

	public ShutDownListener(AuthenticationServer _gs) {
		my_gs = _gs;
	}

	public void run() {
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try {
			my_gs.serverSock.close();
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		try {
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(my_gs.groupList);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	// This is the end of the ShutDownListener class
}

class AutoSave extends Thread {
	public AuthenticationServer my_gs;

	public AutoSave(AuthenticationServer _gs) {
		my_gs = _gs;
	}

	public void run() {
		do {
			try {
				Thread.sleep(300000); // Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
				} catch (Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					outStream.writeObject(my_gs.groupList);
				} catch (Exception e) {
					System.err.println("Error with autosave");
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			} catch (Exception e) {
				System.out.println("Autosave Interrupted");
			}
		} while (true);
	}
	// This is the end of the AutoSave class
}
