/*
 * Used specifically for the readMessages method
 * Just keeps message and text pairs so they can be stored kind of as tuples in an ArrayList
 */

public class MessageAndText implements java.io.Serializable {

    private static final long serialVersionUID = 4L;
    private Message message;
    private byte[] text;

    public MessageAndText(Message _message, byte[] _text) {
        message = _message;
        text = _text;
    }

    public Message getMessage() {
        return message;
    }

    public byte[] getText() {
        return text;
    }
}
