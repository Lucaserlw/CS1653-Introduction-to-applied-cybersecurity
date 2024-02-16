import java.util.Hashtable;
import java.util.ArrayList;

import javax.crypto.SecretKey;

public class GroupKeyMap implements java.io.Serializable {
    private static final long serialVersionUID = 324567L;

    private Hashtable<String, ArrayList<SecretKey>> keyMap;

    public GroupKeyMap() {
        keyMap = new Hashtable<String, ArrayList<SecretKey>>();
    }

    // Adds a new key for the group to use
    public void addGroupKeys(String group, ArrayList<SecretKey> keys) {
        keyMap.put(group, keys);
    }

    public ArrayList<SecretKey> getGroupKeys(String group) {
        return keyMap.get(group);
    }
}
