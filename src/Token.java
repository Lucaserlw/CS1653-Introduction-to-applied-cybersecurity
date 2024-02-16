import java.util.ArrayList;

public class Token implements UserToken, java.io.Serializable {

    private static final long serialVersionUID = 3102101517070539670L;
    private String subject;
    private ArrayList<String> groupList;
    private Envelope ht; // Host token
    private byte[] signature;

    public Token(String _subject, ArrayList<String> _groupList, Envelope _ht, byte[] _signature) {
        subject = _subject;
        groupList = new ArrayList<String>();
        if (_groupList != null) {
            groupList.addAll(_groupList);
        }
        ht = _ht;
        signature = _signature;
    }

    public String getSubject() {
        return subject;
    }

    public ArrayList<String> getGroups() {
        return groupList;
    }

    public Envelope getHostToken() {
        return ht;
    }

    public byte[] getSignature() {
        return signature;
    }

    public boolean addGroup(String _group) {
		if (!groupList.contains(_group)) {
			groupList.add(_group);
			return true;
		}
		else return false;
	}
}
