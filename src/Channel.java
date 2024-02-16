import java.util.ArrayList;

/*
 * Object to respresent a channel
 * Keeps track of group, name, and owner
 * Keeps ArrayList of message objects in channel
 * Ideally message objects are stored in order that they are sent
 * No strict checks to maintain this policy, though
 * Stored in MessageServer.channelList, which is serialized to ChannelList.bin
 */

class Channel implements java.io.Serializable, Comparable<Channel> {
    private static final long serialVersionUID = 2L;
    private String group;
    private String name;
    private String owner;

    private ArrayList<Message> messages;

    public Channel(String _owner, String _group, String _name) {
        group = _group;
        name = _name;
        owner = _owner;
        messages = new ArrayList<Message>();
    }

    public synchronized Message getMessage(int index) {
        return messages.get(index);
    }

    public synchronized void addMessage(Message message) {
        messages.add(message);
    }

    public synchronized boolean removeMessage(Message message) {
        return false;
    }

    public synchronized void removeMessage(int index) {
        messages.remove(index);
    }

    public synchronized String getGroup() {
        return group;
    }

    public synchronized String getName() {
        return name;
    }

    public synchronized String getOwner() {
        return owner;
    }

    public synchronized ArrayList<Message> getMessages() {
        return messages;
    }

    public int compareTo(Channel rhs) {
		if (group.compareTo(rhs.getGroup()) == 0) {
            if (name.compareTo(rhs.getName()) == 0) {
                return 0;
            } else if (name.compareTo(rhs.getName()) < 0) {
                return -1;
            } else {
                return 1;
            }
        } else if (group.compareTo(rhs.getGroup()) < 0) {
            return -2;
        } else {
            return 2;
        }
	}
}