[![Open in Visual Studio Code](https://classroom.github.com/assets/open-in-vscode-718a45dd9cf7e7f842a935f5ebbe5719a5e09af4491e668f4dbf3b35d5cca122.svg)](https://classroom.github.com/online_ide?assignment_repo_id=11288014&assignment_repo_type=AssignmentRepo)

# Messaging Service
Our system is a messaging service similar in functionality to Discord. Given that our service is built on interfaces meant for a distributed file-sharing system, there are a few key differences.

### Authentication Server
Client applications can connect to the authentication server and request an authorization and authentication token which can be used to verify identity to host servers. Logged in client applications can also create, delete and manage groups through the authentication server, Administrators have the additional ability to add and remove users from the service.

### Host Servers
Host servers are somewhat analagous to Discord servers. Within each host server are communication channels, managed as files. Unlike in a Discord server where channel access is managed within the server, channel access is managed by system-wide groups in our service. To be clear, a system-wide group can be responsible for multiple channels across multiple different host servers.

### Groups
Any user in the system can create a group and add or remove users from the group. Unlike Discord, a user is not given the option to accept or decline membership in a group (at least I don't think we implement that). Groups are responsible for ownership of channels accross host servers. In this system, multiple groups cannot be given access to or held responsible for the same channel. Instead, one would have to create a new group containing all members from both groups and then create channels for that group.

### Channels
Communication channels are represented by files located on host servers. Within these files are text messages (represented in Unicode or something). Each message must have an associated sender. Only the message sender can edit their message. Both the message sender and the responsible group owner should be able to delete the message. 
