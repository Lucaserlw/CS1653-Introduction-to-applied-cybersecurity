# Usage Instructions

## Running the Authentication Server

To start the Authentication Server:
 - Enter the directory containing `RunAuthenticationServer.class`
 - Type `java -cp .:../lib/bcprov-jdk18ob-175.jar RunAuthenticationServer [port number]`

Note that the port number argument to `RunAuthenticationServer` is optional.  This argument specifies the port that the Authentication Server will listen to.  If unspecified, it defaults to port 8765.

When the authentication server is first started, there are no users or groups. Since there must be an administrator of the system, the user is prompted via the console to enter a username. This name becomes the first user and is a member of the *ADMIN* group.  No groups other than *ADMIN* will exist.

## Running the Message Server

The message server needs the authentication server's public key to verify token signatures. After running the authentication server and before running the message server, copy `AuthPublic.bin` to the same directory as `RunMessageServer.class`.

To start the Message Server:
 - Enter the directory containing `RunMessageServer.class`
 - Type `java -cp .:../lib/bcprov-jdk18ob-175.jar  RunMessageServer [port number]`

Note that the port number argument to `RunMessageServer` is optional.  This argument speficies the port that the Message Server will list to. If unspecified, it defaults to port 4321.

The message server will create a `messages/` directory inside the working directory if one does not exist. The host server is now online.

## Running the Command-Line Interface

The CLI needs the authentication server's public key for authentication. After running the authentication server and before running the CLI, copy `AuthPublic.bin` to the same directory as `MyClientApp.class`.

To start the Command-Line Interface:
 - Enter the directory containing `MyClientApp.class`
 - Type `java -cp .:../lib/bcprov-jdk18ob-175.jar  MyClientApp`

##### Connecting and Logging In
You will be prompted to connect to the authentication server immediately upon running the CLI program. Enter the server name for the server the authentication server is running on and enter the appropriate port number from earlier. Once you have connected to the authentication server, enter your username and password. If you have just started the program for the first time, use the username and password from when you started the Authentication Server earlier. If there is no further output upon entering your username and password, try restarting this process and make sure the server name and port number are correct.

## Working with the Authentication Server

Upon logging in to the authentication server, you should see output similar to the message below.
```
-- AUTHENTICATION SERVER OPTIONS --
1. See Admin Options
2. See Group Options
3. Leave Authentication Server
Enter your choice: 
```

Input the correct integer to use one of the options. Note that you will not be able to use any of the Admin options if you are not in the *ADMIN* group.

#### Admin Options
Upon selecting the admin options, you will see three options for how to proceed.
```
--- ADMIN OPTIONS ---
1. Create User
2. Delete User
3. Go Back
Enter your choice: 
```
If you choose to create or delete a user, you will be prompted to enter a username.

Notable restrictions:
* You cannot create a user if another user has the same username.

#### Group Options
Upon selecting the group options, you will see six options for how to proceed.
```
--- GROUP OPTIONS ---
1. Create Group
2. Delete Group
3. Add User to Group
4. Remove User from Group
5. List Group Members
6. Go Back
Enter your choice: 
```
If you choose to create or delete a group, you will be asked for a group name. If you want to add a user to a group or remove a user from a group, you will be asked for a group name followed by a username. If you want to list group members, you will prompted for a group name.

Notable restrictions:
* You cannot create a group if another group has the same name.
* You cannot delete a group if you are not the owner of that group.
* You cannot add a user to a group if you are not the owner of that group.
* You cannot remove a user from a group if you are not the owner of that group.
* You cannot list the members of a group if you are not a member of that group.

#### Connecting to a Message Server
To connect to a message server, you must first disconnect from the authentication server using its last option, 3 or 4 depending on whether you are logged in as an admin.
You will see a menu like the one below.
```
--- SYSTEM CONNECTION OPTIONS ---
1. Connect to Authentication Server
2. Connect to Message Server
3. Exit Service
```
Choose option 2 to connect to a message server. As you were previously with the authentication server, you will be asked to enter a server and a port number. You will not be asked for username and password as you should have a token by this point. If this is your first time connecting to this host server, you will be asked to verify that the fingerprint is correct. You should recieve the fingerprint from an external channel of communication. It is visible the first time the message server is run. 

## Working with Message Servers

#### Channel Options
Once you are connected to a message server, you will be presented with a menu like the one below.
```
--- CHANNEL OPTIONS ---
1. Enter Channel
2. Create Channel
3. Delete Channel
4. Refresh Token
5. Refresh Group Keys
6. Disconnect from Message Server
Enter your choice: 
```
If you have not yet created a channel, you should use option 2 to create a channel. You will be prompted for a group name and a channel name. The created channel will only be accessible to members of the specified group. If you choose to enter a channel, you will be given a numbered list of channels that you have access to. You can enter a number to enter any one of them. A similar menu will come up if you choose to delete a channel, except the channel will be deleted instead of being entered.
Notable restrictions:
* You cannot enter a channel for which you are not in the associated group. You will not even be given the option.
* You cannot create a channel for a group which you are not a member of.
* You cannot create a channel in a group with the same name as another channel in that group.
* You cannot delete a channel of a group which you are not a member of. You will not even be given the option.
* You cannot delete a channel that you are not the owner of. A channel's creator is its owner. The owner of the group does not own all channels in the group.


### Refreshing Tokens and Group Token
Any time your membership in a group changes, you will need to request a new user token from the authentication server. You can do this by with option 4. You will also need to refresh your group keys with option 5. Even if you are not added to a new group, you should probably refresh your group keys any time a user is removed from your group.

#### Message Options
Once you enter a channel by creating it or otherwise, you will see a menu like the one below.
```
--- MESSAGE OPTIONS ---
1. Read Messages
2. Write Message
3. Edit Message
4. Delete Message
5. Go Back
Enter your choice: 
```
These options pertain to the group you are in at the moment. These options will not go away until you hit option 5 to go back. From here, you can choose option 1 to print all channel messages to the screen. You can choose option 2 to write a message in this channel. You can choose option 3 to edit an already written message. You will be prompted with a numbered list of messages and asked for the replacement text upon selecting one. Option 4 will give you a numbered list of messages and you can choose a number to delete the corresponding message.
Notable restrictions:
* You cannot edit a message you aren't the author of.
* You cannot delete a message you aren't the author of.
* You cannot write or edit a message to be greater than 8192 bytes.

### Proof of Work

To prevent Denial of Service attacks, we have implemented proof of work. Any time you try to perform an channel of group operation in a message server, your computer will solve a computational problem before sending the message. Your computer will have to perform around 1 million hashes on average before sending a message.

## Logging In as Another User

If you'd like to log in as another user, you'll have to use option 3, `Exit Service`, in the outermost menu. From there you can run `java MyClientApp` again and restart the process, but log in with a different username than the admin one.
