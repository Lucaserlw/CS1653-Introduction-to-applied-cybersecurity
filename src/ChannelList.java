import java.util.ArrayList;
import java.util.Collections;

/*
 * Maintains an ArrayList of all channels in the host server
 * Can be found as MessageServer.channelList
 * Stored in ChannelList.bin
 */

public class ChannelList implements java.io.Serializable {
		
	private static final long serialVersionUID = 3L;
	private ArrayList<Channel> channels;
	
	public ChannelList() {
		channels = new ArrayList<Channel>();
	}
	
	public synchronized void addChannel(Channel channel) {
		channels.add(channel);
	}

	public synchronized Channel addChannel(String group, String name, String owner) {
		Channel channel = new Channel(owner, group, name);
		channels.add(channel);
		return channel;
	}
	
	public synchronized boolean removeChannel(String group, String name) {
		for (int i = 0; i < channels.size(); i++) {
			if ((group.compareTo(channels.get(i).getGroup()) == 0) && (name.compareTo(channels.get(i).getName()) == 0)) {
				channels.remove(i);
                return true;
			}
		}
		return false;
	}
	
	public synchronized boolean checkChannel(String group, String name) {
		for (int i = 0; i < channels.size(); i++) {
			if ((group.compareTo(channels.get(i).getGroup()) == 0) && (name.compareTo(channels.get(i).getName()) == 0)) {
				return true;
			}
		}
		return false;
	}
	
    public synchronized Channel getChannel(String group, String name) {
        for (int i = 0; i < channels.size(); i++) {
			if ((group.compareTo(channels.get(i).getGroup()) == 0) && (name.compareTo(channels.get(i).getName()) == 0)) {
				return channels.get(i);
			}
		}
		return null;
    }

	public synchronized ArrayList<Channel> getChannels() {
		Collections.sort(channels);
		return channels;
	}
}
