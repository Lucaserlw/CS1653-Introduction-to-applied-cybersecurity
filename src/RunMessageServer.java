public class RunMessageServer {
    public static void main(String[] args) {
		if (args.length > 0) {
			try {
				MessageServer server = new MessageServer(Integer.parseInt(args[0]));
				server.start();
			}
			catch (NumberFormatException e) {
				System.out.printf("Enter a valid port number or pass no arguments to use the default port (%d)\n", MessageServer.SERVER_PORT);
			}
		}
		else {
			MessageServer server = new MessageServer();
			server.start();
		}
	}
}
