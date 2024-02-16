import java.util.Scanner;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/*
 * A Client App that allows the user to send/recieve messages through channels by either registering for an
 * account or logging into an already created account. This client app should ultimately connect to
 * the authentication and host server to be able to carry out these actions...
 */

public class MyClientApp {

    private static String publicKeyFile = "ClientPublic.bin";
    private static String privateKeyFile = "ClientPrivate.bin";
    private static String masterKeyFile = "ClientMaster.bin";

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecretKey masterKey;
    private CryptoSuite suite;

    private boolean proceed = true;
    private boolean isInAuth = true;
    private Scanner scanner;

    private AuthenticationClient authClient = null;
    private MessageClient msgClient = null;
    private UserToken token = null;
    private GroupKeyMap keyMap = null;
    private Channel channel = null;
    public HostList hostList = null;
    private IntermediateCLI inter;

    public MyClientApp() {
        inter = new IntermediateCLI();
    }

    public static void main(String[] args) {
        MyClientApp clientApp = new MyClientApp();
        clientApp.loadKeys();
        clientApp.loadHostList();

        // This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListenerClient(clientApp));

        // Autosave Daemon. Saves lists every 5 minutes
		AutoSaveClient aSave = new AutoSaveClient(clientApp);
		aSave.setDaemon(true);
		aSave.start();
        clientApp.start();
    }

    public void start() {

        scanner = new Scanner(System.in);

        System.out.println("Welcome to MyClientApp!");

        while (proceed) {
            if (authClient == null || !authClient.isConnected()) { // Not connected to authentication client
                connectAuth();
            } else if (!authClient.hasSession()) { // Must connect to authentication client to get token
                getAuthSessionKey();
            } else if (keyMap == null) {
                getGroupKeys();
            }  else if (isInAuth) {
                authOptions();
            } else if (msgClient == null || !msgClient.isConnected()) {
                connectOptions();
            } else if (!msgClient.hasSession()) {
                getHostSessionKey();
            } else if (token == null) {
                getToken();
                getGroupKeys();
            } else if (channel == null) {
                channelOptions();
            } else {
                messageOptions();
            }
        }
    }

    private void connectOptions() {
        System.out.println("\n--- SYSTEM CONNECTION OPTIONS ---");
        System.out.println("1. Connect to Authentication Server");
        System.out.println("2. Connect to Message Server");
        System.out.println("3. Exit Service");
        int choice;
            do {
                System.out.print("Enter your choice: ");
                while (!scanner.hasNextInt()) {
                    System.out.println("Please enter an integer.");
                    scanner.nextLine();
                }
                choice = scanner.nextInt();
                scanner.nextLine();
            } while (choice < 1 || choice > 3 );
            switch (choice) {
                case 1:
                    connectAuth();
                    isInAuth = true;
                    break;
                case 2:
                    connectMessage();
                    break;
                default:
                    proceed = false;
                    break;
            }
    }

    private void authOptions() {
        System.out.println("\n-- AUTHENTICATION SERVER OPTIONS --");
        System.out.println("1. See Admin Options");
        System.out.println("2. See Group Options");
        System.out.println("3. Leave Authentication Server");
        int choice;
        do {
            System.out.print("Enter your choice: ");
            while (!scanner.hasNextInt()) {
                System.out.println("Please enter an integer.");
                scanner.nextLine();
            }
            choice = scanner.nextInt();
            scanner.nextLine();
        } while (choice < 1 || choice > 3 );
        switch (choice) {
            case 1:
                adminOptions();
                break;
            case 2:
                groupOptions();
                break;
            default:
                isInAuth = false;
                break;
        }
    }

    private void adminOptions() {
        System.out.println("\n--- ADMIN OPTIONS ---");
        System.out.println("1. Create User");
        System.out.println("2. Delete User");
        System.out.println("3. Go Back");
        int choice;
        do {
            System.out.print("Enter your choice: ");
            while (!scanner.hasNextInt()) {
                System.out.println("Please enter an integer.");
                scanner.nextLine();
            }
            choice = scanner.nextInt();
            scanner.nextLine();
        } while (choice < 1 || choice > 3 );
        switch (choice) {
            case 1:
                createUser();
                break;
            case 2:
                deleteUser();
                break;
            default:
                break;
        }
    }

    private void groupOptions(){
        System.out.println("\n--- GROUP OPTIONS ---");
        System.out.println("1. Create Group");
        System.out.println("2. Delete Group");
        System.out.println("3. Add User to Group");
        System.out.println("4. Remove User from Group");
        System.out.println("5. List Group Members");
        System.out.println("6. Go Back");
        int choice;
        do {
            System.out.print("Enter your choice: ");
            while (!scanner.hasNextInt()) {
                System.out.println("Please enter an integer.");
                scanner.nextLine();
            }
            choice = scanner.nextInt();
            scanner.nextLine();
        } while (choice < 1 || choice > 6 );
        switch (choice) {
            case 1:
                createGroup();
                break;
            case 2:
                deleteGroup();
                break;
            case 3:
                addUserToGroup();
                break;
            case 4:
                removeUserFromGroup();
                break;
            case 5:
                listMembers();
                break;
            default:
                break;
        }
    }

    private void connectAuth() {
        if (authClient == null || !authClient.isConnected()) {
            System.out.print("Enter the authentication server name: ");
            String server = scanner.nextLine();
            System.out.print("Enter the appropriate port number: ");
            while (!scanner.hasNextInt()) {
                System.out.println("Please enter an integer for port number.");
                scanner.nextLine();
            }
            int port = scanner.nextInt();
            scanner.nextLine();
            AuthenticationClient newClient = new AuthenticationClient();
            if (newClient.connect(server, port)) {
                authClient = newClient;
                System.out.println("Successfully connected to authentication server.");
            } else {
                System.out.println("Failed to connect to authentication server.");
            }
        } else {
            System.out.println("Already connected to authentication server.");
        }
    }

    private void getAuthSessionKey() {
        System.out.print("Enter your username to get authentication session key: ");
        String username = scanner.nextLine();

        if (authClient.getSessionKey(username, inter, suite)) {
            System.out.println("Successfully got authentication session key.");
        } else {
            System.out.println("Failed to get authentication session key.");
        }
    }

    private void getHostSessionKey() {
        if (msgClient.getSessionKey(publicKey, privateKey, inter, suite)) {
            System.out.println("Successfully got host session key.");
        } else {
            System.out.println("Failed to get host session key.");
        }
    }

    private void getToken() {
        UserToken newToken = authClient.getToken(msgClient.getHostToken());
        if (newToken != null) {
            token = newToken;
            System.out.println("Successfully got fresh token.");
        } else {
            System.out.println("Failed to get fresh token.");
        }
    }

    private void getGroupKeys() {
        GroupKeyMap newKeyMap = authClient.getGroupKeys();
        if (newKeyMap != null) {
            keyMap = newKeyMap;
            System.out.println("Successfully got fresh group keys.");
        } else {
            System.out.println("Failed to get fresh group keys.");
        }
    }
    
    private void createUser() {
        System.out.print("Enter a username: ");
        String username = scanner.nextLine();
        System.out.print("Enter a password: ");
        String password = scanner.nextLine();
        if (authClient.createUser(username, password)) {
            System.out.println("Successfully created user.");
        } else {
            System.out.println("Failed to create user.");
        }
    }

    private void deleteUser() {
        System.out.print("Enter a username: ");
        String username = scanner.nextLine();
        if (authClient.deleteUser(username)) {
            System.out.println("Successfully deleted user.");
        } else {
            System.out.println("Failed to delete user.");
        }
    }

        private void createGroup() {
        System.out.print("Enter the group name: ");
        String groupName = scanner.nextLine();

        if (authClient.createGroup(groupName)) {
            System.out.println("Successfully created group.");
        } else {
            System.out.println("Failed to create group.");
        }
    }

    private void deleteGroup() {
        System.out.print("Enter the group name: ");
        String groupName = scanner.nextLine();

        if (authClient.deleteGroup(groupName)) {
            System.out.println("Successfully deleted group.");
        } else {
            System.out.println("Failed to delete group.");
        }
    }

    private void addUserToGroup() {
        System.out.print("Enter the group name: ");
        String groupName = scanner.nextLine();
        System.out.print("Enter a username: ");
        String username = scanner.nextLine();

        if (authClient.addUserToGroup(username, groupName)) {
            System.out.println("Successfully added user to group.");
        } else {
            System.out.println("Failed to add user to group.");
        }
    }

    private void removeUserFromGroup() {
        System.out.print("Enter the group name: ");
        String groupName = scanner.nextLine();
        System.out.print("Enter a username: ");
        String username = scanner.nextLine();

        if (authClient.deleteUserFromGroup(username, groupName)) {
            System.out.println("Successfully removed user from group.");
        } else {
            System.out.println("Failed to remove user from group.");
        }
    }

    private void listMembers() {
        System.out.print("Enter the group name: ");
        String groupName = scanner.nextLine();
        List<String> members = authClient.listMembers(groupName);
        if (members != null) {
            System.out.printf("Listing all %d members of group:\n", members.size());
            for (String m: members) {
                System.out.printf("\t%s\n", m);
            }
        } else {
            System.out.println("Failed to get members of group.");
        }
    }

    private void channelOptions() {
        System.out.println("\n--- CHANNEL OPTIONS ---");
        System.out.println("1. Enter Channel");
        System.out.println("2. Create Channel");
        System.out.println("3. Delete Channel");
        System.out.println("4. Refresh Token");
        System.out.println("5. Refresh Group Keys");
        System.out.println("6. Disconnect from Message Server");
        int choice;
        do {
            System.out.print("Enter your choice: ");
            while (!scanner.hasNextInt()) {
                System.out.println("Please enter an integer.");
                scanner.nextLine();
            }
            choice = scanner.nextInt();
            scanner.nextLine();
        } while (choice < 1 || choice > 6 );
        switch (choice) {
            case 1:
                System.out.println("Select a channel to enter:");
                channel = selectChannel();
                break;
            case 2:
                createChannel();
                break;
            case 3:
                deleteChannel();
                break;
            case 4:
                getToken();
                break;
            case 5:
                getGroupKeys();
                break;
            default:
                msgClient.disconnect();
                msgClient = null;
                token = null;
                break;
        }
    }

    private Channel selectChannel() {
        List<Channel> channels = msgClient.getChannels(token);
        if (channels == null) {
            System.out.println("Failed to get channels.");
        } else if (channels.size() == 0) {
            System.out.println("You have no channels.");
        } else {
            for (int i = 0; i < channels.size(); i++) {
                System.out.printf("%d. Group: %-12s    Channel: %s\n", i+1, channels.get(i).getGroup(), channels.get(i).getName());
            }
            int choice;
            do {
                System.out.print("Enter your choice: ");
                while (!scanner.hasNextInt()) {
                    System.out.println("Please enter an integer.");
                    scanner.nextLine();
                }
                choice = scanner.nextInt();
                scanner.nextLine();
            } while (choice < 1 || choice > channels.size());
            return channels.get(choice - 1);
        }
        return null;
    }

    private void messageOptions() {
        System.out.println("\n--- MESSAGE OPTIONS ---");
        System.out.println("1. Read Messages");
        System.out.println("2. Write Message");
        System.out.println("3. Edit Message");
        System.out.println("4. Delete Message");
        System.out.println("5. Go Back");
        int choice;
        do {
            System.out.print("Enter your choice: ");
            while (!scanner.hasNextInt()) {
                System.out.println("Please enter an integer.");
                scanner.nextLine();
            }
            choice = scanner.nextInt();
            scanner.nextLine();
        } while (choice < 1 || choice > 5 );
        switch (choice) {
            case 1:
                printMessages();
                break;
            case 2:
                sendMessage();
                break;
            case 3:
                editMessage();
                break;
            case 4:
                deleteMessage();
                break;
            default:
                channel = null;
                break;
        }
    }

    private void connectMessage() {
        System.out.print("Enter the message server name: ");
        String server = scanner.nextLine();
        System.out.print("Enter the appropriate port number: ");
        while (!scanner.hasNextInt()) {
            System.out.println("Please enter an integer.");
            scanner.nextLine();
        }
        int port = scanner.nextInt();
        scanner.nextLine();
        MessageClient newClient = new MessageClient();
        if (newClient.connect(server, port)) {
            msgClient = newClient;
            System.out.println("Successfully connected to message server");
        } else {
            System.out.println("Failed to connect to message server.");
        }
    }

    private void createChannel() {
        System.out.print("Enter the group name: ");
        String groupName = scanner.nextLine();
        System.out.print("Enter the channel name: ");
        String channelName = scanner.nextLine();

        Channel newChannel = msgClient.createChannel(groupName, channelName, token);
        if (newChannel != null) {
            channel = newChannel;
            System.out.println("Successfully created channel.");
        } else {
            System.out.println("Failed to create channel.");
        }
    }

    private void deleteChannel() {
        System.out.println("Select a channel to delete:");
        Channel delChannel = selectChannel();
        if (delChannel == null) {
            System.out.println("Failed to select a channel to delete");
        } else {
            if (msgClient.deleteChannel(delChannel, token)) {
                System.out.println("Successfully deleted channel.");
            } else {
                System.out.println("Failed to delete channel.");
            }
        }
    }

    private void sendMessage() {
        System.out.print("Enter a message: ");
        String text = scanner.nextLine();

        Message message = msgClient.sendMessage(channel, text, token, keyMap);

        if (message != null) {
            System.out.println("Successfully sent message.");
        } else {
            System.out.println("Failed to send message.");
        }
    }

    private void printMessages() {
        List<MessageAndText> messages = msgClient.readMessages(channel, token);
        if (messages == null) {
            System.out.println("Failed to get messages.");
        } else if (messages.size() == 0) {
            System.out.println("Channel has no messages.");
        } else {
            System.out.println("Channel messages:");
            for (int i = 0; i < messages.size(); i++) {
                String owner = messages.get(i).getMessage().getOwner();
                String text = getMessageText(messages.get(i));
                System.out.printf("%d. %s: %s\n", i+1, owner, text);
            }
        }
    }

    private Message selectMessage() {
        List<MessageAndText> messages = msgClient.readMessages(channel, token);
        if (messages == null) {
            System.out.println("Failed to get messages.");
        } else if (messages.size() == 0) {
            System.out.println("Channel has no messages.");
        } else {
            System.out.println("Select a message:");
            for (int i = 0; i < messages.size(); i++) {
                String owner = messages.get(i).getMessage().getOwner();
                String text = getMessageText(messages.get(i));
                System.out.printf("%d. %s: %s\n", i+1, owner, text);
            }
            int choice;
            do {
                System.out.print("Enter your choice: ");
                while (!scanner.hasNextInt()) {
                    System.out.println("Please enter an integer.");
                    scanner.nextLine();
                }
                choice = scanner.nextInt();
                scanner.nextLine();
            } while (choice < 1 || choice > messages.size());
            return messages.get(choice - 1).getMessage();
        }
        return null;
    }

    private void editMessage() {
        Message message = selectMessage();
        if (message == null) {
            System.out.println("Failed to select message to edit.");
        } else {
            System.out.print("Enter a replacement message: ");
            String text = scanner.nextLine();
            if (msgClient.setMessage(message, text, token, keyMap)) {
                System.out.println("Successfully edited message.");
            } else {
                System.out.println("Failed to edit message.");
            }
        }
    }

    private void deleteMessage() {
        Message message = selectMessage();
        if (message == null) {
            System.out.println("Failed to select message to delete.");
        } else {
            if (msgClient.deleteMessage(message, token)) {
                System.out.println("Successfully deleted message.");
            } else {
                System.out.println("Failed to delete message.");
            }
        }
    }

    // Used to coordinate UI and client interactions
    // There are cases where I don't want MyClientApp handling crypto and whatnot but I also don't want clients reading input directly
    // Made this class so I can pass instance as a function parameter and clients can call it
    private class IntermediateCLI implements IntermediaryInterface {
        public String askPassword() {
            System.out.print("Please enter your password: ");
            String pass = scanner.nextLine();
            return pass;
        }

        public boolean checkFingerprint(String server, String fingerprint) {
            System.out.printf("Server and fingerprint: (%s, %s)\n", server, fingerprint);
            Boolean pair = hostList.checkPair(server, fingerprint);
            if (pair == null) {
                System.out.println("Is the pair of server and fingerprint above correct? (y/n)");
                String ans = scanner.nextLine();
                if (ans.equals("y")) {
                    hostList.putPair(server, fingerprint);
                    return true;
                } else {
                    return false;
                }
            }
            return pair;
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

    private void loadHostList() {
        try {
            FileInputStream hostListF = new FileInputStream("HostList.bin");
            ObjectInputStream hostListStream = new ObjectInputStream(hostListF);
			hostList = (HostList) hostListStream.readObject();
            hostListStream.close();
        } catch (FileNotFoundException e) {
			System.out.println("Failed to fetch public and host list. Generating new host list...");
            hostList = new HostList();
		} catch (IOException e) {
			System.out.println("Error reading from host list file");
			System.exit(-1);
		} catch (ClassNotFoundException e) {
			System.out.println("Error reading from host list file");
			System.exit(-1);
		}
    }

    private String getMessageText(MessageAndText mt) {
        Message msg = mt.getMessage();
        String group = msg.getGroup();
        byte[] tBytes = mt.getText();
        int keyIndex = msg.getKeyIndex();
        List<SecretKey> groupKeys = keyMap.getGroupKeys(group);
        if (keyIndex >= groupKeys.size()) return null;
        SecretKey gk = groupKeys.get(keyIndex);
        byte[] iv = msg.getIv();
        String text = suite.decryptStringAES(tBytes, gk, iv);
        return text;
    }
}


// Saves the HostList to file upon shutdown
class ShutDownListenerClient extends Thread {
	public MyClientApp my_cli;

	public ShutDownListenerClient(MyClientApp _cli) {
		my_cli = _cli;
	}

	public void run() {
		ObjectOutputStream outStream;
		try {
			outStream = new ObjectOutputStream(new FileOutputStream("HostList.bin"));
			outStream.writeObject(my_cli.hostList);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
    // This is the end of the ShutdownListenerClient class
}

// Saves the HostList to file every 5 minutes
class AutoSaveClient extends Thread {
	public MyClientApp my_cli;

	public AutoSaveClient(MyClientApp _cli) {
		my_cli = _cli;
	}

	public void run() {
		do {
			try {
				Thread.sleep(300000);
				ObjectOutputStream outStream;
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("HostList.bin"));
					outStream.writeObject(my_cli.hostList);
				} catch (Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			} catch (Exception e) {
				System.out.println("Autosave Interrupted");
			}
		} while (true);
	}
    // This is the end of the AutoSaveClient class
}