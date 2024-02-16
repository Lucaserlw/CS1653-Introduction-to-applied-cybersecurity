/* This list represents the users on the server */
import java.util.*;
import javax.crypto.SecretKey;


	public class UserList implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 7600343803563417992L;
		private Hashtable<String, User> list = new Hashtable<String, User>();
		
		public synchronized void addUser(String username, SecretKey sk, byte[] salt)
		{
			User newUser = new User(sk, salt);
			list.put(username, newUser);
		}
		
		public synchronized void deleteUser(String username)
		{
			list.remove(username);
		}
		
		public synchronized boolean checkUser(String username)
		{
			if(list.containsKey(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		
		public synchronized ArrayList<String> getUserGroups(String username)
		{
			return list.get(username).getGroups();
		}
		
		public synchronized ArrayList<String> getUserOwnership(String username)
		{
			return list.get(username).getOwnership();
		}
		
		public synchronized void addGroup(String user, String groupname)
		{
			list.get(user).addGroup(groupname);
		}
		
		public synchronized void removeGroup(String user, String groupname)
		{
			list.get(user).removeGroup(groupname);
		}
		
		public synchronized void addOwnership(String user, String groupname)
		{
			list.get(user).addOwnership(groupname);
		}
		
		public synchronized void removeOwnership(String user, String groupname)
		{
			list.get(user).removeOwnership(groupname);
		}

		public synchronized SecretKey getUserMasterKey(String user) {
			return list.get(user).getMasterKey();
		}
		public synchronized byte[] getUserSalt(String user) {
			return list.get(user).getSalt();
		}
	
	class User implements java.io.Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;
		private SecretKey masterKey;
		private byte[] salt;
		
		public User(SecretKey _masterKey, byte[] _salt)
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
			masterKey = _masterKey;
			salt = _salt;
		}
		
		public ArrayList<String> getGroups()
		{
			return groups;
		}
		
		public ArrayList<String> getOwnership()
		{
			return ownership;
		}
		

		public void addGroup(String group)
		{
			groups.add(group);
		}
		
		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
			}
		}
		
		public void addOwnership(String group)
		{
			ownership.add(group);
		}
		
		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}
		public void setMasterKey(SecretKey _masterKey, byte[] _salt) {
			masterKey = _masterKey;
			salt = _salt;
		}

		public SecretKey getMasterKey() {
			return masterKey;
		}

		public byte[] getSalt() {
			return salt;
		}
	}
}	
