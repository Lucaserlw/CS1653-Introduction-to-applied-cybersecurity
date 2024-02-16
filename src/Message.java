/*
 * Stores information about a given message
 * Keeps track of group, channel, and owner (sender)
 * Also keeps track of name of file where text is stored
 * Text files are stored in messages directory
 * None of these attributes should ever change
 */

class Message implements java.io.Serializable, Comparable<Message> {
    
    private static final long serialVersionUID = 1L;
    private String group;
    private String channel;
    private String owner;
    private String path;
    private int keyIndex;
    private byte[] iv;
    private int length;

    public Message(String _owner, String _group, String _channel, String _path, int _keyIndex, byte[] _iv, int _length) {
        group = _group;
        channel = _channel;
        owner = _owner;
        path = _path;
        keyIndex = _keyIndex;
        iv = _iv;
        length = _length;
    }

    public synchronized String getGroup() {
        return group;
    }

    public synchronized String getChannel() {
        return channel;
    }

    public synchronized String getOwner() {
        return owner;
    }

    public synchronized String getPath() {
        return path;
    }

    public synchronized int getKeyIndex() {
        return keyIndex;
    }

    public synchronized byte[] getIv() {
        return iv;
    }

    public synchronized int getLength() {
        return length;
    }

    public synchronized void setKeyIndex(int _keyIndex) {
        keyIndex = _keyIndex;
    }

    public synchronized void setIv(byte[] _iv) {
        iv = _iv;
    }

    public synchronized void setLength(int _length) {
        length = _length;
    }

	public int compareTo(Message rhs) {
		if (path.compareTo(rhs.getPath())==0)return 0;
		else if (path.compareTo(rhs.getPath())<0) return -1;
		else return 1;
	}
}