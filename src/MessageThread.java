import java.lang.Thread;
import java.net.Socket;
import java.security.PublicKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;

import javax.crypto.SecretKey;

import java.util.ArrayList;

/*
 * Host server thread for handling message-related requests from the user
 * Performs checks for authorization, updates channel list, saves message files, etc.
 */

public class MessageThread extends Thread
{
	private static String MESSAGE_FILE_PREFIX = "msg";
	private static String MESSAGE_FILE_SUFFIX = ".txt";
	private static int MAX_MESSAGE_BYTES = 4096;
	
	private final Socket socket;

	public MessageThread(Socket _socket)
	{
		socket = _socket;
	}

	public void run()
	{
        boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;
            do {
                Envelope e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());
				if (e.getMessage().equals("ENCRYPTEDSESSION")) {
					Envelope challengeResp = challengeClient(input, output);
					if (challengeResp == null) {
						response = decryptAndOperate(e);
					} else {
						response = challengeResp;
					}
					output.writeObject(response);
				} else if (e.getMessage().equals("GETSESSIONKEY")) {
					response = getSessionKey(e);
					output.writeObject(response);
				} else if (e.getMessage().equals("DISCONNECT")) {
					socket.close();
					proceed = false;
				}
            } while (proceed);
        } catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	// This performs a challenge that the client needs to complete before they're allowed to do things like send and read messages
	// Returns null if the challenge was successful
	private Envelope challengeClient(ObjectInputStream input, ObjectOutputStream output) {
		try {
			Envelope env = new Envelope("CHALLENGE");
			byte[] m = MessageServer.suite.generateSalt(); // Using salt function for m because it's 8 random bytes
			env.addObject(m);
			env.addObject(MessageServer.bBits); // Number of leading 0-bits needed
			output.writeObject(env);
			Envelope resp = (Envelope)input.readObject();
			if (resp.getObjContents().size() < 1) return new Envelope("FAIL-BADENVELOPE");
			byte[] n = (byte[])resp.getObjContents().get(0);
			if (n == null) return new Envelope("FAIL-BADBYTES");
			if (n.length > 8) return new Envelope("FAIL-BADBYTES");
			if (MessageServer.suite.checkProblem(m, n, MessageServer.bBits)) return null;
			return new Envelope("FAIL-BADHASH");
		} catch (Exception e) {
			e.printStackTrace(System.out);
		}
		return new Envelope("ERROR");

	}

	// Decrypts parts of envelope, performs requested operation, and returns message
	private Envelope decryptAndOperate(Envelope env1) {
		try {
			// Check envelope contents for null
			if (env1.getObjContents().size() < 3) return new Envelope("FAIL-BADENVELOPE");
			byte[] enc = (byte[])env1.getObjContents().get(0);
			byte[] enc_iv = (byte[])env1.getObjContents().get(1);
			Envelope ht = (Envelope)env1.getObjContents().get(2);
			if (enc == null) return new Envelope("FAIL-BADENCRYPTION");
			if (enc_iv == null) return new Envelope("FAIL-BADIV");
			if (ht == null) return new Envelope("FAIL-BADHOSTTOKEN");

			// Get session key
			if (ht.getObjContents().size() < 2) return new Envelope("FAIL-BADHOSTTOKEN");
			Envelope decHt = decryptHostToken(ht);
			SecretKey sk = (SecretKey)decHt.getObjContents().get(0);

			// Decrypt message envelope
			Envelope env2 = MessageServer.suite.decryptEnvelopeAES(enc, enc_iv, sk);
			if (!env2.getMessage().equals("OPERATIONDATA")) return new Envelope("FAIL-BADINNERENVELOPE");
			Envelope opInfo = (Envelope)env2.getObjContents().get(0);
			System.out.printf("\tEncrypted request: %s\n", opInfo.getMessage());
			Token token = (Token)env2.getObjContents().get(1);

			// Verify the signature on the token
			PublicKey authPub = getAuthPublicKey(); // Read from AuthPublic.bin
			if (!MessageServer.suite.verifyToken(token, authPub)) return new Envelope("FAIL-BADUSERTOKEN");

			// Perform the requested operation and respond;
			Envelope response;
			switch (opInfo.getMessage()){
				case "GETCHANNELS":
					response = getChannels(token);
					break;
				case "CREATECHANNEL":
					response = createChannel(opInfo, token);
					break;
				case "DELETECHANNEL":
					response = deleteChannel(opInfo, token);
					break;
				case "SENDMESSAGE":
					response = sendMessage(opInfo, token);
					break;
				case "DELETEMESSAGE":
					response = deleteMessage(opInfo, token);
					break;
				case "SETMESSAGE":
					response = setMessage(opInfo, token);
					break;
				case "READMESSAGES":
					response = readMessages(opInfo, token);
					break;
				default:
					response = new Envelope("FAIL-BADOPERATION");
					break;
			}

			// Encrypt the response if server successully extracted session key
			Envelope renv = MessageServer.suite.encryptEnvelopeAES(response, "ENCRYPTEDSESSION", sk);
			return renv;
		} catch (Exception e) {
			e.printStackTrace(System.out);
		}
		return new Envelope("ERROR");
	}

	public static synchronized boolean inGroup(UserToken token, String group) {
		List<String> groups = token.getGroups();
		for (String g: groups) {
			if (group.equals(g)) {
				return true;
			}
		}
		return false;
	}

	public static synchronized Envelope getSessionKey(Envelope e) {
		try {
			if (e.getObjContents().size() < 1) return new Envelope("FAIL-BADENVELOPE");
			PublicKey userPub = (PublicKey) e.getObjContents().get(0);
			if (userPub == null) return new Envelope("FAIL-BADPUBLICKEY");

			// Generate the response with session key, host token, and host server's public key
			SecretKey sk = MessageServer.suite.generateKey();
			Envelope hostToken = new Envelope("HOSTTOKEN");
			hostToken.addObject(sk);
			Envelope ht = MessageServer.suite.encryptEnvelopeAES(hostToken, "HOSTTOKEN", MessageServer.masterKey);
			byte[] encSk = MessageServer.suite.encryptKeyRSA(sk, userPub);
			Envelope outer = new Envelope("OK");
			outer.addObject(MessageServer.publicKey);
			outer.addObject(encSk);
			outer.addObject(ht);
			return outer;
		} catch (Exception ex) {
			ex.printStackTrace(System.out);
		}
		return null;
	}

	public static synchronized Envelope getChannels(UserToken token) {
		if (token == null) { // Token is null
			return new Envelope("FAIL-BADTOKEN");
		}
		ArrayList<Channel> channels = new ArrayList<Channel>();
		for (Channel c: MessageServer.channelList.getChannels()) {
			if (inGroup(token, c.getGroup())) {
					channels.add(c);
				}
		}
		Envelope response = new Envelope("OK");
		response.addObject(channels);
		return response;
	}

	public static synchronized Envelope createChannel(Envelope e, UserToken token) {
		if (e.getObjContents().size() < 2) {
			return new Envelope("FAIL-BADENVELOPE");
		}
		String group = (String) e.getObjContents().get(0);
		String name = (String) e.getObjContents().get(1);
		if (group == null) { // Group name string is null
			return new Envelope("FAIL-BADGROUPNAME");
		}
		if (name == null) { // Channel name string is null
			return new Envelope("FAIL-BADCHANNELNAME");
		}
		if (token == null) { // Token is null
			return new Envelope("FAIL-BADTOKEN");
		}
		if (!inGroup(token, group)) { // User not in group
			return new Envelope("FAIL-UNAUTHORIZEDGROUP");
		}
		if (MessageServer.channelList.checkChannel(group, name)) { // Channel with same name already exists in group
			return new Envelope("FAIL-CHANNELEXISTS");
		}
		Channel channel = MessageServer.channelList.addChannel(group, name, token.getSubject());
		Envelope response = new Envelope("OK");
		response.addObject(channel);
		return response;
	}

	public  static synchronized Envelope deleteChannel(Envelope e, UserToken token) {
		if (e.getObjContents().size() < 1) {
			return new Envelope("FAIL-BADENVELOPE");
		}
		Channel channel = (Channel) e.getObjContents().get(0);
		if (channel == null) { // Channel is null
			return new Envelope("FAIL-BADCHANNEL");
		}
		if (token == null) { // Token is null
			return new Envelope("FAIL-BADTOKEN");
		}
		Channel server_channel = MessageServer.channelList.getChannel(channel.getGroup(), channel.getName());
		if (server_channel == null) { // Channel does not exist
			return new Envelope("FAIL-NOCHANNEL");
		}
		if (!token.getSubject().equals(server_channel.getOwner())) { // User is not owner of channel
			return new Envelope("FAIL-UNAUTHORIZED");
		}
		// TODO: Check that all message files actually exist
		for (Message m: server_channel.getMessages()) {
			File message_file = new File("messages/" + m.getPath());
				message_file.delete();
		}
		MessageServer.channelList.removeChannel(server_channel.getGroup(), server_channel.getName());
		Envelope response = new Envelope("OK");
		return response;
	}

	public static synchronized Envelope sendMessage(Envelope e, UserToken token) {
		if (e.getObjContents().size() < 4) {
			return new Envelope("FAIL-BADENVELOPE");
		}
		Channel channel = (Channel) e.getObjContents().get(0);
		byte[] tBytes = (byte[]) e.getObjContents().get(1);
		int keyIndex = (int) e.getObjContents().get(2);
		byte[] iv = (byte[]) e.getObjContents().get(3);
		
		if (channel == null) {
			return new Envelope("FAIL-BADCHANNEL");
		}
		if (tBytes == null) {
			return new Envelope("FAIL-BADTEXT");
		}
		if (token == null) {
			return new Envelope("FAIL-BADTOKEN");
		}
		Channel server_channel = MessageServer.channelList.getChannel(channel.getGroup(), channel.getName());
		if (server_channel == null) {
			return new Envelope("FAIL-NOCHANNEL");
		}
		if (!inGroup(token, server_channel.getGroup())) {
			return new Envelope("FAIL-UNAUTHORIZED");
		}
		File messages_dir = new File("messages");
		try {
			File message_file = File.createTempFile(MESSAGE_FILE_PREFIX, MESSAGE_FILE_SUFFIX, messages_dir);
			if (tBytes.length > MAX_MESSAGE_BYTES) { // Message text is too long
			}
			FileOutputStream file_out = new FileOutputStream(message_file);
			file_out.write(tBytes);
			file_out.close();
			Message message = new Message(token.getSubject(), channel.getGroup(), channel.getName(), message_file.getName(), keyIndex, iv, tBytes.length);
			server_channel.addMessage(message);
			Envelope response = new Envelope("OK");
			response.addObject(message);
			return response;
		} catch (IOException ex) {
			return new Envelope("ERROR-IOEXCEPTION");
		}
	}

	public static synchronized Envelope deleteMessage(Envelope e, UserToken token) {
		if (e.getObjContents().size() < 1) {
			return new Envelope("FAIL-BADENVELOPE");
		}
		Message message = (Message) e.getObjContents().get(0);
		if (message == null) { // Message is null
			return new Envelope("FAIL-BADMESSAGE");
		}
		if (token == null) { // Token is null
			return new Envelope("FAIL-BADTOKEN");
		}
		Channel channel = MessageServer.channelList.getChannel(message.getGroup(), message.getChannel());
		if (channel == null) { // Channel does not exist
			return new Envelope("FAIL-NOCHANNEL");
		}
		if (!inGroup(token, channel.getGroup())) { // User doesn't have access to channel
			return new Envelope("FAIL-UNAUTHORIZEDCHANNEL");
		}
		Envelope response = new Envelope("FAIL-BADPATH"); // Message path does not correspond to actual message
		ArrayList<Message> messages = channel.getMessages(); 
		for (int i = 0; i < messages.size(); i++) {
			if (!messages.get(i).getOwner().equals(token.getSubject())) { // User is not message owner
					response = new Envelope("FAIL-UNAUTHORIZEDMESSAGE");
			} else {
				if (messages.get(i).compareTo(message) == 0) {
					File message_file = new File("messages/" + message.getPath());
					if (!message_file.exists()) { // Message file does not exist
						response = new Envelope("ERROR-BADPATH");
					} else {
						message_file.delete();
						channel.removeMessage(i);
						response = new Envelope("OK");
						break;
					}
				}
			}
		}
		return response;
	}

	public static synchronized Envelope setMessage(Envelope e, UserToken token) {
		if (e.getObjContents().size() < 4) {
			return new Envelope("FAIL-BADENVELOPE");
		}
		Message message = (Message)e.getObjContents().get(0);
		byte[] tBytes = (byte[])e.getObjContents().get(1);
		int keyIndex = (int)e.getObjContents().get(2);
		byte[] iv = (byte[])e.getObjContents().get(3);
		if (message == null) { // Message is null
			return new Envelope("FAIL-BADMESSAGE");
		}
		if (tBytes == null) { // Text is null
			return new Envelope("FAIL-BADTEXT");
		} if (token == null) { // Token is null
			return new Envelope("FAIL-BADTOKEN");
		}
		Channel channel = MessageServer.channelList.getChannel(message.getGroup(), message.getChannel());
		if (channel == null) { // Channel doesn't exist
			return new Envelope("FAIL-NOCHANNEL");
		}
		if (!inGroup(token, channel.getGroup())) { // User doesn't have access to channel
			return new Envelope("FAIL-UNAUTHORIZEDCHANNEL");
		}
		Envelope response = new Envelope("FAIL-BADPATH"); // Message path doesnot correspond to actual message
		ArrayList<Message> messages = channel.getMessages();
		// TODO: Refactor below for better control flow
		for (Message m: messages) {
			if (message.compareTo(m) == 0) {
				if (!m.getOwner().equals(token.getSubject())) { // User is not message owner
					response = new Envelope("FAIL-UNAUTHORIZEDMESSAGE");
				} else {
					File message_file = new File("messages/" + m.getPath());
					if (!message_file.exists()) { // Message file does not exist
						response = new Envelope("ERROR-BADPATH");
					} else {
						if (tBytes.length > MAX_MESSAGE_BYTES) { // Message is too long
							response = new Envelope("FAIL-TEXTTOOLONG");
						} else {
							try {
							FileOutputStream file_out = new FileOutputStream(message_file);
							file_out.write(tBytes);
							file_out.close();
							m.setKeyIndex(keyIndex);
							m.setIv(iv);
							m.setLength(tBytes.length);
							} catch (IOException ex) {
								return new Envelope("ERROR-IOEXCEPTION");
							}
							response = new Envelope("OK");
						}
					}
					break;
				}
			}
		}
		return response;
	}

	public static synchronized Envelope readMessages(Envelope e, UserToken token) {
		if (e.getObjContents().size() < 1) {
			return new Envelope("FAIL-BADENVELOPE");
		}
		Channel channel = (Channel) e.getObjContents().get(0);
		if (channel == null) { // Channel is null
			return new Envelope("FAIL-BADCHANNEL");
		}
		if (token == null) { // Token is null
			return new Envelope("FAIL-BADTOKEN");
		}
		Channel server_channel = MessageServer.channelList.getChannel(channel.getGroup(), channel.getName());
		if (server_channel == null) { // Channel does not exist
			return new Envelope("FAIL-NOCHANNEL");
		}
		if (!inGroup(token, server_channel.getGroup())) { // User doesn't have access to channel
			return new Envelope("FAIL-UNAUTHORIZEDCHANNEL");
		}
		// TODO: Check that all message files actually exist
		try {
		ArrayList<MessageAndText> messages = new ArrayList<MessageAndText>();
			for (Message m: server_channel.getMessages()) {
				File message_file = new File("messages/" + m.getPath());
				FileInputStream file_in = new FileInputStream(message_file);
				byte[] buf = new byte[m.getLength()];
				file_in.read(buf);
				file_in.close();
				messages.add(new MessageAndText(m, buf));
			}
			Envelope response = new Envelope("OK");
			response.addObject(messages);
			return response;
		} catch (IOException ex) {
			return new Envelope ("ERROR-IOEXCEPTION");
		}
	}

	public static Envelope decryptHostToken(Envelope ht) {
		try {
			byte[] encHt = (byte[]) ht.getObjContents().get(0);
            byte[] iv = (byte[]) ht.getObjContents().get(1);
            return MessageServer.suite.decryptEnvelopeAES(encHt, iv, MessageServer.masterKey);
		} catch (Exception e) {
			e.printStackTrace(System.out);
		}
		return null;
	}

	private static PublicKey getAuthPublicKey() {
		try {
			FileInputStream authPubF = new FileInputStream("AuthPublic.bin");
            ObjectInputStream authPubStream = new ObjectInputStream(authPubF);
			PublicKey authPub = (PublicKey) authPubStream.readObject();
            authPubStream.close();
			return authPub;
		} catch (Exception e) {
			e.printStackTrace(System.out);
		}
		return null;
	}
}