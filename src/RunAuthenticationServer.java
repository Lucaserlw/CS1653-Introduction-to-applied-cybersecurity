/* Driver program for FileSharing Group Server */

public class RunAuthenticationServer {
	
	public static void main(String[] args) {
		if (args.length> 0) {
			try {
				AuthenticationServer server = new AuthenticationServer(Integer.parseInt(args[0]));
				server.start();
			}
			catch (NumberFormatException e) {
				System.out.printf("Enter a valid port number or pass no arguments to use the default port (%d)\n", AuthenticationServer.SERVER_PORT);
			}
		}
		else {
			AuthenticationServer server = new AuthenticationServer();
			server.start();
		}
	}
}
