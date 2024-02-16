import java.util.Hashtable;

// Client class that maintains a list of authenticated host servers for client to reference when connecting
public class HostList implements java.io.Serializable {
    private static final long serialVersionUID = 3243245677L;
    private Hashtable<String, String> hosts; // Using Hashtable because it's synchronized while HashMap is not

    public HostList() {
        hosts = new Hashtable<String, String>();
    }

    synchronized public void putPair(String server, String fingerprint) {
        hosts.put(server, fingerprint);
    }


    /* 
     * Checks whether a pair is in the hashmap
     * If server not in hashmap, returns true
     * If server in hashmap, return true iff fingerprint matches
     */
    synchronized public Boolean checkPair(String server, String fingerprint) {
        String value = hosts.get(server);
        if (value == null) {
            return null;
        }
        if (value.equals(fingerprint)) {
            return true;
        }
            return false;
    }
}