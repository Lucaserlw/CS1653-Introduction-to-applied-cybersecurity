import java.util.ArrayList;
import java.nio.ByteBuffer;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/*
 * User client for sending messaging-related network requests to host server
 */

public class MessageClient extends Client {

	private CryptoSuite suite = null; // Crypto suite from the client app
	private SecretKey sk = null; // Session key
	private Envelope ht = null; // Host token

    public boolean getSessionKey(PublicKey pub, PrivateKey priv, IntermediaryInterface inter, CryptoSuite _suite) {
        suite = _suite;
        try {
            Envelope env = null, resp = null;
            env = new Envelope("GETSESSIONKEY");
            env.addObject(pub);
            output.writeObject(env);
            resp = (Envelope) input.readObject();
            if (resp.getMessage().equals("OK")) {
                PublicKey hPub = (PublicKey) resp.getObjContents().get(0);
                String fingerprint = suite.getFingerprint(hPub);
                String server = sock.getInetAddress().getHostName();
                if (inter.checkFingerprint(server, fingerprint)) {
                    System.out.println("Successfully authenticated server.");
                    byte[] encSk = (byte[]) resp.getObjContents().get(1);
                    sk = suite.decryptKeyRSA(encSk, priv);
                    ht = (Envelope) resp.getObjContents().get(2);
                    return true;
                } else {
                    System.out.println("Failed to authenticate the host server due to fingerprint.");
                }
            } else {
                System.out.printf("Error getting session key: %s\n", resp.getMessage());
            }
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return false;
    }

    public Channel createChannel(String group, String name, UserToken token) {
        Envelope env = new Envelope("CREATECHANNEL");
        env.addObject(group);
        env.addObject(name);
        try {
            if(!sendEncrypted(env, token)) return null;
            env = receiveEncrypted();
            if (env.getMessage().compareTo("OK") == 0) {
                return (Channel) env.getObjContents().get(0);
			} else {
				System.out.printf("Error creating channel: %s\n", env.getMessage());
                return null;
			}
        } catch (Exception e) {
			e.printStackTrace();
		}
        return null;
    }

    public boolean deleteChannel(Channel channel, UserToken token) {
        Envelope env = new Envelope("DELETECHANNEL");
        env.addObject(channel);
        try {
            if(!sendEncrypted(env, token)) return false;
            env = receiveEncrypted();
            if (env.getMessage().compareTo("OK") == 0) {
                return true;
			} else {
				System.out.printf("Error deleting channel: %s\n", env.getMessage());
                return false;
			}
        } catch (Exception e) {
			e.printStackTrace();
		}
        return false;
    }

    public Message sendMessage(Channel channel, String text, UserToken token, GroupKeyMap keyMap) {
        try {
            String groupname = channel.getGroup();
            ArrayList<SecretKey> groupKeys = keyMap.getGroupKeys(groupname);
            int keyIndex = groupKeys.size() - 1;
            SecretKey gk = groupKeys.get(keyIndex);

            System.out.printf("Using group key version %s\n", keyIndex);

            byte[] iv = suite.generateAesIv();
            byte[] tBytes = suite.encryptMessageAES(text, gk, iv);

            Envelope env = new Envelope("SENDMESSAGE");
            env.addObject(channel);
            env.addObject(tBytes);
            env.addObject(keyIndex);
            env.addObject(iv);
            if(!sendEncrypted(env, token)) return null;
            env = receiveEncrypted();
            if (env.getMessage().compareTo("OK") == 0) {
                return (Message) env.getObjContents().get(0);
            } else {
				System.out.printf("Error sending message: %s\n", env.getMessage());
                return null;
			}
        } catch (Exception e) {
			e.printStackTrace();
		}
        return null;
    }

    public boolean deleteMessage(Message message, UserToken token) {
        Envelope env = new Envelope("DELETEMESSAGE");
        env.addObject(message);
        try {
            if(!sendEncrypted(env, token)) return false;
            env = receiveEncrypted();
            if (env.getMessage().compareTo("OK") == 0) {
                return true;
			} else {
				System.out.printf("Error deleting message: %s\n", env.getMessage());
                return false;
			}
        } catch (Exception e) {
			e.printStackTrace();
		}
        return false;
    }

    public boolean setMessage(Message message, String text, UserToken token, GroupKeyMap keyMap) {
        try {
            String groupname = message.getGroup();
            ArrayList<SecretKey> groupKeys = keyMap.getGroupKeys(groupname);
            int keyIndex = groupKeys.size() - 1;
            SecretKey gk = groupKeys.get(keyIndex);

            System.out.printf("Using group key version %s\n", keyIndex);

            byte[] iv = suite.generateAesIv();
            byte[] tBytes = suite.encryptMessageAES(text, gk, iv);

            Envelope env = new Envelope("SETMESSAGE");
            env.addObject(message);
            env.addObject(tBytes);
            env.addObject(keyIndex);
            env.addObject(iv);
            if(!sendEncrypted(env, token)) return false;
            env = receiveEncrypted();
            if (env.getMessage().compareTo("OK") == 0) {
                return true;
			} else {
				System.out.printf("Error setting message: %s\n", env.getMessage());
                return false;
			}
        } catch (Exception e) {
			e.printStackTrace();
		}
        return false;
    }

	@SuppressWarnings("unchecked")
    public ArrayList<Channel> getChannels(UserToken token) {
        Envelope env = new Envelope("GETCHANNELS");
        try {
            if(!sendEncrypted(env, token)) return null;
            env = receiveEncrypted();
            if (env.getMessage().equals("OK")) {
                ArrayList<Channel> channels = (ArrayList<Channel>) env.getObjContents().get(0);
				return channels;
			} else {
				System.out.printf("Error getting channels: %s\n", env.getMessage());
                return null;
			}
        } catch (Exception e) {
			e.printStackTrace();
		}
        return null;
    }

	@SuppressWarnings("unchecked")
    public ArrayList<MessageAndText> readMessages(Channel channel, UserToken token) {
        Envelope env = new Envelope("READMESSAGES");
        env.addObject(channel);
        try {
            if(!sendEncrypted(env, token)) return null;
            env = receiveEncrypted();
            if (env.getMessage().equals("OK")) {
                ArrayList<MessageAndText> messages = (ArrayList<MessageAndText>) env.getObjContents().get(0);
                return messages;
			} else {
				System.out.printf("Error reading messages: %s\n", env.getMessage());
                return null;
			}
        } catch (Exception e) {
			e.printStackTrace();
		}
        return null;
    }

    // Returns whether client has full valid session tokens
	public boolean hasSession() {
		if (suite == null) return false;
		if (sk == null) return false;
		if (ht == null) return false;
		return true;
	}

    public Envelope getHostToken() {
        return ht;
    }

    	// Encrypts envelope and then sends it
	private boolean sendEncrypted(Envelope env, UserToken token) {
        try {
            Envelope inner = new Envelope("OPERATIONDATA");
            inner.addObject(env);
            inner.addObject(token);
            Envelope outer = suite.encryptEnvelopeAES(inner, "ENCRYPTEDSESSION", sk);
            outer.addObject(ht);
            /* 
            * What are in the indices in outer after the code above executes?
            * 0: A byte[] representing inner encrypted with session key
            * 1: A byte[] representing initialization vector used to encrypt inner
            * 2: An Envelope containing the server's host token for this session
            */
			output.writeObject(outer);
			return true;
		} catch(Exception e) {
			e.printStackTrace(System.out);
			return false;
		}
	}

    // This recieved encrypted messages and also accounts for challenges
	private Envelope receiveEncrypted() {
		try {
			Envelope response = (Envelope)input.readObject();
            if (response.getMessage().equals("CHALLENGE")){
                byte[] m = (byte[])response.getObjContents().get(0);
                int b = (int)response.getObjContents().get(1);
                byte[] n = solveChallenge(m, b);
                Envelope chal = new Envelope("CHALLENGE");
                chal.addObject(n);
                output.writeObject(chal);
                response = (Envelope) input.readObject();
            }
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

    private byte[] solveChallenge(byte[] m, int b) {
        try {
            long startTime = System.nanoTime();
            for (long i = 1; i <= Long.MAX_VALUE; i++) {
                ByteBuffer n = ByteBuffer.allocate(8);
                n.putLong(i);
                if (suite.checkProblem(m, n.array(), b)) {
                    long endTime = System.nanoTime();
                    double timed = (endTime - startTime) / 1000000000.0;
                    System.out.printf("Tried %d hashes in %f seconds to solve challenge.\n", i, timed);
                    return n.array();
                }
            }
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }

        return null;
    }
}
