/* Implements the GroupClient Interface */

import java.util.ArrayList;

import javax.crypto.SecretKey;

public class AuthenticationClient extends Client {
	
	private CryptoSuite suite = null; // Crypto suite from the client app
	private SecretKey sk = null; // Session key
	Envelope at = null;
 
	 public UserToken getToken(Envelope ht)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;
		 		 	
			//Tell the server to return a token.
			message = new Envelope("GETTOKEN");
			message.addObject(ht); //Add user name string
			if (!sendEncrypted(message)) return null;
		
			response = receiveEncrypted();
			
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				token = (UserToken) response.getObjContents().get(0);
				return token;
			} else {
				System.out.printf("Error getting token: %s\n", response.getMessage());
			}
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
		
	 }

	 public GroupKeyMap getGroupKeys() {
		try {
			Envelope env = null, resp = null;
			env = new Envelope("GETGROUPKEYS");
			if (!sendEncrypted(env)) return null;
			resp = receiveEncrypted();

			if (resp.getMessage().equals("OK")) {
				return (GroupKeyMap)resp.getObjContents().get(0);
			} else {
				System.out.printf("Error getting group keys: %s\n", resp.getMessage());
			}
		} catch (Exception e) {
			e.printStackTrace(System.out);
		}
		return null;
	 }
	 
	 public boolean createUser(String username, String password)
	 {
		 try
			{
				Envelope message = null, response = null;

				// Generate salt and hash password
				byte[] salt = suite.generateSalt();
				SecretKey mk = suite.computeKey(password, salt);

				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(username);
				message.addObject(mk);
				message.addObject(salt);
				if (!sendEncrypted(message)) return false;

				response = receiveEncrypted();
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				} else {
					System.out.printf("Error creating user: %s\n", response.getMessage());
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUser(String username)
	 {
		 try
			{
				Envelope message = null, response = null;
			 
				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name
				if (!sendEncrypted(message)) return false;

				response = receiveEncrypted();
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				} else {
					System.out.printf("Error deleting user: %s\n", response.getMessage());
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean createGroup(String groupname)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(groupname); //Add the group name string
				if (!sendEncrypted(message)) return false;

				response = receiveEncrypted();
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				} else {
					System.out.printf("Error creating group user: %s\n", response.getMessage());
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteGroup(String groupname)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(groupname); //Add group name string
				if (!sendEncrypted(message)) return false;

				response = receiveEncrypted();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				} else {
					System.out.printf("Error deleting group: %s\n", response.getMessage());
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	public ArrayList<String> listMembers(String group) {
		try {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(group); //Add group name string
			if (!sendEncrypted(message)) return null;

			response = receiveEncrypted();
			 
			 //If server indicates success, return the member list
			if(response.getMessage().equals("OK"))
			{ 
				return (ArrayList<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			} else {
				System.out.printf("Error listing members of group: %s\n", response.getMessage());
			}
				
			 return null;
			 
		} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
		}
	}
	 
	public boolean addUserToGroup(String username, String groupname)
	{
		try {
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				if (!sendEncrypted(message)) return false;
			
				response = receiveEncrypted();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				} else {
					System.out.printf("Error adding user to group: %s\n", response.getMessage());
				}	
				
				return false;
		} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
		}
	}
	 
	public boolean deleteUserFromGroup(String username, String groupname)
	{
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				if (!sendEncrypted(message)) return false;
			
				response = receiveEncrypted();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				} else {
					System.out.printf("Error removing user from group: %s\n", response.getMessage());
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	}

	public boolean getSessionKey(String username, IntermediaryInterface ask, CryptoSuite _suite) {
		suite = _suite;
		try {
			Envelope message = null, response = null;
			message = new Envelope("GETSESSIONKEY");
			message.addObject(username);
			output.writeObject(message);

			response = (Envelope)input.readObject();
			if (!response.getMessage().equals("OK")) {
				System.out.printf("Error getting session key: %s\n", response.getMessage());
				return false;
			}

			// Extract objects of outermost message
			byte[] encSesh = (byte[])response.getObjContents().get(0);
			byte[] iv = (byte[])response.getObjContents().get(1);
			byte[] salt = (byte[])response.getObjContents().get(2);

			// Get user's password to get master key
			String password = ask.askPassword();
			SecretKey mk = suite.computeKey(password, salt);

			// Decrypt session information envelope with master key
			Envelope sesh = suite.decryptEnvelopeAES(encSesh, iv, mk);
			sk = (SecretKey)sesh.getObjContents().get(0);
			at = (Envelope)sesh.getObjContents().get(1);

			return true;
		} catch (Exception e) {
			e.printStackTrace(System.out);
			return false;
		}
	}

	// Encrypts envelope and then sends it
	private boolean sendEncrypted(Envelope env) {
		Envelope enc = suite.encryptEnvelopeAES(env, "ENCRYPTEDSESSION", sk);
		enc.addObject(at);
		/* 
		 * What are in the indices in enc after the code above executes?
		 * 0: A byte[] representing env encrypted with session key
		 * 1: A byte[] representing initialization vector used to encrypt env
		 * 2: A byte[] representing the server's authentication token for this session
		 * 3: A byte[] representing the initializaton vector with which the authentication token was encrypted
		 */
		try {
			output.writeObject(enc);
			return true;
		} catch(Exception e) {
			e.printStackTrace(System.out);
			return false;
		}
	}

	private Envelope receiveEncrypted() {
		try {
			Envelope response = (Envelope)input.readObject();
			if (response.getMessage().equals("ENCRYPTEDSESSION")) {
				byte[] enc = (byte[])response.getObjContents().get(0);
				byte[] iv = (byte[])response.getObjContents().get(1);
				Envelope env = suite.decryptEnvelopeAES(enc, iv, sk);
				return env;
			} else {
				return response;
			}
		} catch (Exception e) {
			e.printStackTrace(System.out);
		}
		return null;
	}

	// Returns whether client has full valid session tokens
	public boolean hasSession() {
		if (suite == null) return false;
		if (sk == null) return false;
		if (at == null) return false;
		return true;
	}
}