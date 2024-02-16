/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;

import javax.crypto.SecretKey;

public class AuthenticationThread extends Thread 
{
	private final Socket socket;
	private AuthenticationServer my_gs;

	public AuthenticationThread(Socket _socket, AuthenticationServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}
	
	public void run()
	{
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;
				
				if (message.getMessage().equals("GETSESSIONKEY")) {// Client wants a token
					response = getSessionKey(message);
					output.writeObject(response);
				} else if (message.getMessage().equals("ENCRYPTEDSESSION")) {
					response = decryptAndOperate(message);
					output.writeObject(response);
				} else if(message.getMessage().equals("DISCONNECT")) { //Client wants to disconnect
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				} else {
					response = new Envelope("FAIL"); //Server does not understand client request
					output.writeObject(response);
				}
			}while(proceed);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}


	private synchronized Envelope getSessionKey(Envelope env) {
		if (env.getObjContents().size() < 1) return new Envelope("FAIL-BADENVELOPE");
		String username = (String)env.getObjContents().get(0);
		if (username == null) return new Envelope("FAIL-BADUSERNAME");

		if (!my_gs.userList.checkUser(username)) return new Envelope("FAIL-BADREQUESTER");
		
		SecretKey mk = my_gs.userList.getUserMasterKey(username);
		byte[] salt = my_gs.userList.getUserSalt(username);
		SecretKey sk = my_gs.suite.generateKey();
		Envelope auth = new Envelope("AUTHTOKEN"); // {String username, SecretKey sk}
		auth.addObject(username);
		auth.addObject(sk);
		Envelope at = my_gs.suite.encryptEnvelopeAES(auth, "AUTHTOKEN", my_gs.masterKey);
		Envelope outer = new Envelope("OK");
		outer.addObject(sk);
		outer.addObject(at);
		Envelope enc = my_gs.suite.encryptEnvelopeAES(outer, "OK", mk);
		enc.addObject(salt);
		return enc;
	}


	// Decrypts parts of envelope, performs requested operation, and returns message
	private Envelope decryptAndOperate(Envelope env1) {
		try {
			// Check envelope contents for null
			if (env1.getObjContents().size() < 3) return new Envelope("FAIL-BADENVELOPE");
			byte[] enc = (byte[])env1.getObjContents().get(0);
			byte[] enc_iv = (byte[])env1.getObjContents().get(1);
			Envelope at = (Envelope)env1.getObjContents().get(2);
			if (enc == null) return new Envelope("FAIL-BADENCRYPTION");
			if (enc_iv == null) return new Envelope("FAIL-BADIV");
			if (at == null) return new Envelope("FAIL-BADAUTHTOKEN");

			// Get session key
			if (at.getObjContents().size() < 2) return new Envelope("FAIL-BADAUTHTOKEN");
			Envelope decAt = decryptAuthToken(at);
			String requester = (String)decAt.getObjContents().get(0);
			SecretKey sk = (SecretKey)decAt.getObjContents().get(1);

			// Decrypt message envelope
			Envelope env2 = my_gs.suite.decryptEnvelopeAES(enc, enc_iv, sk);

			// Perform the requested operation and respond;
			Envelope response;
			switch (env2.getMessage()){
				case "CUSER":
					response = createUser(requester, env2);
					break;
				case "DUSER":
					response = deleteUser(requester, env2);
					break;
				case "CGROUP":
					response = createGroup(requester, env2);
					break;
				case "DGROUP":
					response = deleteGroup(requester, env2);
					break;
				case "LMEMBERS":
					response = listMembers(requester, env2);
					break;
				case "AUSERTOGROUP":
					response = addUserToGroup(requester, env2);
					break;
				case "RUSERFROMGROUP":
					response = removeUserFromGroup(requester, env2);
					break;
				case "GETTOKEN":
					response = getToken(requester, env2);
					break;
				case "GETGROUPKEYS":
					response = getGroupKeys(requester);
					break;
				default:
					response = new Envelope("FAIL-BADOPERATION");
					break;
			}

			// Encrypt the response if server successully extracted session key
			Envelope renv = my_gs.suite.encryptEnvelopeAES(response, "ENCRYPTEDSESSION", sk);
			return renv;
		} catch (Exception e) {
			e.printStackTrace(System.out);
		}
		return new Envelope("ERROR");
	}

	private synchronized Envelope removeUserFromGroup(String requester, Envelope env) {
		if (env.getObjContents().size() < 2) return new Envelope("FAIL-BADENVELOPE");
		String username = (String)env.getObjContents().get(0);
		String groupname = (String)env.getObjContents().get(1);
		if (username == null) return new Envelope("FAIL-BADUSERNAME");
		if (groupname == null) return new Envelope("FAIL-BADGROUPNAME");
		
		if (!my_gs.userList.checkUser(requester)) return new Envelope("FAIL-BADREQUESTER");
		if (!my_gs.groupList.checkGroup(groupname)) return new Envelope("FAIL-NOGROUP");
		if (!my_gs.userList.checkUser(username)) return new Envelope("FAIL-NOUSER");
		if (!my_gs.groupList.getOwner(groupname).equals(requester)) return new Envelope("FAIL-UNAUTHORIZED");
		if (!my_gs.groupList.getMembers(groupname).contains(username)) return new Envelope("FAIL-USERNOTMEMBER");

		my_gs.userList.removeGroup(username, groupname);
		my_gs.groupList.removeMember(username, groupname);

		// Generate a new secret key since user was removed from group
		SecretKey gk = my_gs.suite.generateKey();
		my_gs.groupList.addGroupKey(groupname, gk);

		// Delete group if owner tries to remove themselves from group
		if (requester.equals(username)) {
			deleteGroupHelper(groupname);
		}
		return new Envelope("OK");
	}

	private synchronized Envelope addUserToGroup(String requester, Envelope env) {
		if (env.getObjContents().size() < 2) return new Envelope("FAIL-BADENVELOPE");
		String username = (String)env.getObjContents().get(0);
		String groupname = (String)env.getObjContents().get(1);
		if (username == null) return new Envelope("FAIL-BADUSERNAME");
		if (groupname == null) return new Envelope("FAIL-BADGROUPNAME");

		if (!my_gs.userList.checkUser(requester)) return new Envelope("FAIL-BADREQUESTER");
		if (!my_gs.groupList.checkGroup(groupname)) return new Envelope("FAIL-NOGROUP");
		if (!my_gs.userList.checkUser(username)) return new Envelope("FAIL-NOUSER");
		if (!my_gs.groupList.getOwner(groupname).equals(requester)) return new Envelope("FAIL-UNAUTHORIZED");
		if (my_gs.groupList.getMembers(groupname).contains(username)) return new Envelope("FAIL-USERALREADYMEMBER");

		my_gs.userList.addGroup(username, groupname);
		my_gs.groupList.addMember(username, groupname);
		return new Envelope("OK");
	}

	private synchronized Envelope listMembers(String requester, Envelope env) {
		if (env.getObjContents().size() < 1) return new Envelope("FAIL-BADENVELOPE");
		String groupname = (String)env.getObjContents().get(0);
		if (groupname == null) return new Envelope("FAIL-BADGROUPNAME");

		if (!my_gs.userList.checkUser(requester)) return new Envelope("FAIL-BADREQUESTER");
		if (!my_gs.groupList.checkGroup(groupname)) return new Envelope("FAIL-NOGROUP");
		ArrayList<String> requesterGroups = my_gs.userList.getUserGroups(requester);
		if(!requesterGroups.contains(groupname)) return new Envelope("FAIL-UNAUTHORIZED");

		ArrayList<String> members = my_gs.groupList.getMembers(groupname);
		Envelope response = new Envelope("OK");
		response.addObject(members);
		return response;
	}
	
	private synchronized Envelope createGroup(String requester, Envelope env) {
		if (env.getObjContents().size() < 1) return new Envelope("FAIL-BADENVELOPE");
		String groupname = (String)env.getObjContents().get(0);
		if (groupname == null) return new Envelope("FAIL-BADGROUPNAME");

		if (!my_gs.userList.checkUser(requester)) return new Envelope("FAIL-BADREQUESTER");
		if (my_gs.groupList.checkGroup(groupname)) return new Envelope("FAIL-GROUPEXISTS");

		SecretKey gk = my_gs.suite.generateKey();
		my_gs.groupList.addGroup(requester, groupname, gk);
		my_gs.userList.addGroup(requester, groupname);
		my_gs.userList.addOwnership(requester, groupname);
		return new Envelope("OK");
	}

	private synchronized Envelope getToken(String requester, Envelope env) {
		if (env.getObjContents().size() < 1) return new Envelope("FAIL-BADENVELOPE");
		Envelope ht = (Envelope)env.getObjContents().get(0);
		if (ht == null) return new Envelope("FAIL-BADHOSTTOKEN");

		if (!my_gs.userList.checkUser(requester)) return new Envelope("FAIL-BADREQUESTER");
		Token token = createToken(requester, ht);
		if (token == null) return new Envelope("FAIL-BADHOSTTOKEN");


		Envelope response = new Envelope("OK");
		response.addObject(token);
		return response;
	}

	private synchronized Envelope getGroupKeys(String requester) {
		try {
			GroupKeyMap keyMap = new GroupKeyMap();
			for (String groupname: my_gs.userList.getUserGroups(requester)) {
				ArrayList<SecretKey> groupKeys = my_gs.groupList.getGroupKeys(groupname);
				keyMap.addGroupKeys(groupname, groupKeys);
			}
			Envelope response = new Envelope("OK");
			response.addObject(keyMap);
			return response;
		} catch (Exception e) {
			e.printStackTrace(System.out);
		}
		return null;
	}

	private synchronized Token createToken(String requester, Envelope ht) {
		// Check that the user exists
		if (my_gs.userList.checkUser(requester)) {
			ArrayList<String> groups = my_gs.userList.getUserGroups(requester);
			Token token = my_gs.suite.signToken(requester, groups, ht);
			return token;
		} else {
			return null;
		}
	}


	private synchronized Envelope deleteGroup(String requester, Envelope env)
	{
		if (env.getObjContents().size() < 1) return new Envelope("FAIL-BADENVELOPE");
		String groupname = (String)env.getObjContents().get(0);
		if (groupname == null) return new Envelope("FAIL-BADGROUPNAME");

		if(!my_gs.userList.checkUser(requester)) return new Envelope("FAIL-BADREQUESTER");
		if(!my_gs.userList.getUserOwnership(requester).contains(groupname)) return new Envelope("FAIL-UNAUTHORIZED");
		
		deleteGroupHelper(groupname);

		return new Envelope("OK");
	}
	

	private synchronized Envelope createUser(String requester, Envelope env) {
		if (env.getObjContents().size() < 3) return new Envelope("FAIL-BADENVELOPE");
		String username = (String)env.getObjContents().get(0);
		SecretKey mk = (SecretKey)env.getObjContents().get(1);
		byte[] salt = (byte[])env.getObjContents().get(2);
		if (username == null) return new Envelope("FAIL-BADUSERNAME");
		if (mk == null) return new Envelope("FAIL-BADMASTERKEY");
		if (salt == null) return new Envelope("FAIL-BADSALT");
		
		if(!my_gs.userList.checkUser(requester)) return new Envelope("FAIL-BADREQUESTER");
		ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
		if(!temp.contains("ADMIN")) return new Envelope("FAIL-UNAUTHORIZED");
		if(my_gs.userList.checkUser(username)) return new Envelope("FAIL-USEREXISTS");
		my_gs.userList.addUser(username, mk, salt);
		return new Envelope("OK");
	}
	

	private synchronized Envelope deleteUser(String requester, Envelope env) {
		if (env.getObjContents().size() < 1) return new Envelope("FAIL-BADENVELOPE");
		String username = (String) env.getObjContents().get(0);
		if (username == null) return new Envelope("FAIL-BADUSERNAME");

		if(!my_gs.userList.checkUser(requester)) return new Envelope("FAIL-BADREQUESTER");

		ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
		if(!temp.contains("ADMIN")) return new Envelope("FAIL-UNAUTHORIZED");
		if(!my_gs.userList.checkUser(username)) return new Envelope("FAIL-BADUSER");

		deleteUserHelper(username);

		return new Envelope("OK");
	}

	private void deleteGroupHelper(String groupname) {
		List<String> deleteFromUsers = my_gs.groupList.getMembers(groupname);
		for(String username: deleteFromUsers)
		{
			my_gs.userList.removeGroup(username, groupname);
		}
		
		String owner = my_gs.groupList.getOwner(groupname);
		my_gs.userList.removeOwnership(owner, groupname);
		
		my_gs.groupList.deleteGroup(groupname);
	}

	private void deleteUserHelper(String username) {
		// Delete owned groups first to lessen work for groupw which were not owned
		List<String> deleteOwnedGroups = new ArrayList<String>();
		for (String groupname: my_gs.userList.getUserOwnership(username)) {
			deleteOwnedGroups.add(groupname);
		}

		for (String groupname: deleteOwnedGroups) {
			deleteGroupHelper(groupname);
		}

		List<String> deleteFromGroups = my_gs.userList.getUserGroups(username);
		for (String groupname: deleteFromGroups) {
			my_gs.groupList.removeMember(username, groupname);

			// Generate a new secret key since user was removed from group
			SecretKey gk = my_gs.suite.generateKey();
			my_gs.groupList.addGroupKey(groupname, gk);
		}
		my_gs.userList.deleteUser(username);
	}

	private Envelope decryptAuthToken(Envelope at) {
		try {
			byte[] encAt = (byte[]) at.getObjContents().get(0);
            byte[] iv = (byte[]) at.getObjContents().get(1);
            return my_gs.suite.decryptEnvelopeAES(encAt, iv, my_gs.masterKey);
		} catch (Exception e) {
			e.printStackTrace(System.out);
		}
		return null;
	}
}
