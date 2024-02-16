# CS 1653 Term Project Phase 4 Writeup

### Group Information

Name | Email | Github
---|---|---
Wuyue Liu | wul5@pitt.edu | Lucaserlw
Jakob Ross | jjr113@pitt.edu | jjr113
Sean Lord | sal244@pitt.edu | LordOfBeans

## Threats

### Threat 5 - Message Reorder, Replay, or Modification

#### Description
When a client communicates with a message or group server this threat states that messages sent between the user and the server can be reordered, saved for a replay attack, or modified by a malicious attacker. The attacker intercepts a username and password meant for a server and replays it to gain access to protected data.

#### Chosen Mechanism
Beside implementing the DH exchange that we did not finished in phase 3, we also need to add something new to insure the integrity, which is using the HMAC. A shared key will be used to calculate an HMAC of each message, that will be sent along with the message. This will will be used by both parties to verify integrity. To implement this feature, a second key is needed. We will derive keys similar to the way SSH does: after the DH exchange creates initial key K, two keys will be created as follows:


 * Encryption Key (Ke): HASH(K || "E")
  * Integrity Key (Ki): HASH(K || "I")

    
Also, in order to against reorder and replay attacks, it is necessary to add a number which will be sent with the message at the beginnning of the session. After every message sent, this number will be incremented by one. When messages are received, they will only be valid if the message number is larger than the largest message number previously seen.
#### Argument
The protocol addresses various types of attacks, namely reorder, replay, and modification attacks. Both reorder and replay attacks are countered by employing session-specific encryption keys and an incrementing session-specific counter.

To prevent replays across different sessions, distinct encryption keys are utilized for each session. Within a single session, messages are accepted only when the counter has been incremented beyond the highest previously observed value, effectively disregarding any replayed messages.

The use of the session-specific counter also thwarts reorder attacks. Despite potential attempts by an attacker to delay or discard messages, the protocol ensures that messages are only accepted in ascending order based on the counter value.
### Threat 6 - Resource Leakage

#### Description

Resource leakage occurs when untrusted host servers expose resources to unauthorized principals. In this context, host servers may be compromised or malicious and share sensitive data with entities that should not have access to it. In our messaging-based system, users can share resources such as messages within these channels. However, with the presence of untrusted host servers, there is a risk of resource leakage, where sensitive information shared within a group or channel may be exposed to unauthorized users.

#### Chosen Mechanism

To protect against resource leakage, we will use group keys for symmetric encryption. Each group will have a unique group key shared among its members. This group key will be used to encrypt resources uploaded to the host server, ensuring that only authorized group members can access them.

  ##### Cryptographic Choices
  
  * To maintain the confidentiality of the group key, we will use asymmetric encryption and secure key distribution mechanisms.
  * We will use a strong symmetric encryption algorithm like AES to encrypt the resources.
  
  ##### Group Key Distribution
  
  * When a new group is created, the group creator generates a group key pair (public and private key).
  * The group creator securely distributes the group's public key to all intended group members through a trusted channel or a public key infrastructure (PKI).
  
  ##### Resource Encryption and Decryption
  
  * When a group member uploads a resource to the host server, the resource is encrypted using the group's shared symmetric encryption key (AES).
  * The encrypted resource is then stored on the host server.
  
  ##### Resource Access
  
  * When a group member wants to access a resource, they request the resource from the host server.
  * The host server, upon receiving the request, verifies the group membership of the requesting principal.
  * If the requester is an authorized group member, the host server uses the group's shared symmetric key to decrypt and provide the resource to the requester.
  * If the requester is not a member of the group, the host server denies access to the resource.
  
  ##### Group Key Rotation
  For added security, group keys should be rotated periodically or when group membership changes. The process is as follows:
  
  * The group administrator generates a new group key pair.
  * The new public key is distributed to all group members.
  * All new resources uploaded to the host server will be encrypted with the new group key.
  * Older resources remain encrypted with the previous group key to ensure backward compatibility.

#### Argument

By using group keys for symmetric encryption, we ensure that only authorized group members can access the resources stored on the host server. Since each group has its unique group key, the confidentiality of resources is maintained even if the host server is compromised. Additionally, periodic group key rotation further enhances security by limiting the damage caused by potential leaks.

### Threat 7 - Token Theft

#### Description

In phase 3, we provided every host server with the same token signed by the authentication server to verify the user's identity. Unfortunately, we cannot trust each host server to act in the users' best interests in a real distributed system where anyone can establish a host server. As a result, we need a mechanism to ensure that tokens are unique to servers. This would ensure that if a user were to log in to a malicious host server, that host server could not pretend to be them by using their authentication token at another server.

#### Chosen Mechanism

To prevent malicious host servers from using a user's authentication token, we have to make sure that authentication tokens are unique to each host server. Unlike Kerberos, our authentication server doesn't know all of the host servers and thus cannot provide the user with a session token for each service they want to use. Instead, we'll have the authentication token take a random challenge provided by the host server and sign that along with the token. Let's look at how that might work below, where the user client $C$ wants to connect to the host server $H$ using a token from authentication server $A$. Since this protocol will occur immediately upon connection, we'll recap a bit of the fingerprint protocol as well.

1. $C \rightarrow H$: $(\text{name}, k_U)$ where $k_U$ is the user's public key.
2. $H$: Select a secure random secret key $K_{CH}$
3. $H$: Encrypt host token $HT = \\{\\text{name}, K_{CH}\\}K_{MH}$ where $K_{MH}$ is the host server's private master key
4. $H \rightarrow C$: $\\{k_H, K_{CH}, HT\\}k_U$ where $k_H$ is the host server's public key
5. $C$: Decrypt with $k_U^{-1}$ to get $k_H$, $K_{CH}$, and $HT$.
6. $C$: Perform fingerprint check with $k_H$
7. $C \rightarrow A$: $(\\{HT\\}S_A, AT)$ where authentication token $AT = \\{\text{user}, S_A\\}K_{MA}$ and $K_{MA}$ is the authentication server's private master key.
8. $A$: Verify the user's identity using $AT$ and $S_A$
9. $A$: Create user group token $GT = \[\text{user}, \text{group info}, HT\]k_A^{-1}$ where $k_A^{-1}$ is the authentication server's private key
10. $A \rightarrow C$: $\\{GT\\}S_A$ where $S_A$ is a previously established session key

After the four-message exchange above, the client can use the group token $GT$ along with the host token $HT$ and the shared secret $K_{CH}$ to perform operations on the host servers with a single message. Let's see a new set of steps that the host server can perform for every request.

1. $C \rightarrow H$: $(\\{\text{operation info}, GT\\}K_{CH}, HT)$
2. $H$: Decrypt $HT$ with private master key $K_{MH}$ to get user's username and $K_{CH}$
3. $H$: Decrypt with $K_{CH}$ to get operation and $GT = \[\text{user}, \text{group info}, HT\]k_A^{-1}$
4. $H$: Confirm that $HT$ in $GT$ matches $HT$ sent by client
5. $H$: Verify $GT$ signature with authentication server's public key $k_{A}$
6. Check that user has valid credentials using the group info in $GT$
7. Perform the operation specified with the operation info

#### Argument

Why this works can be fairly complicated given there are many steps and many moving parts. The main additions to this process from phase 3 are $K_{CH}$ and, by extension, $HT$. Very similarly to how the authentication server's authentication process works, $K_{CH}$ acts like a session key while host token $HT$ allows the host server to get the user's session key without having to store it somewhere. If the host server successfully decrypts a message with $K_{CH}$ found in $HT$, the host server knows that it issued $K_{CH}$.

The main difficulty here is that the host server has no way of verifying the user's identity before issuing $K_{CH}$ and $HT$. For this purpose, we bring in the authentication server. We use $HT$ as a unique identifier in the group token $GT$ so the authentication server can provide a signature verifying that the authentication token was requested with $HT$. Since we can trust the authentication server to authenticate the user, the host server can establish that the token was issued to the correct user with the current host server as the intended recipient.

Now we'll look at some ways a malicious host $M$ server may try to cheat and how those attempts would be thwarted. Let's say a user $U$ logs into a malicious host server using the protocol above and performs an operation such that the host server recieves group token $GT_M$ verified with host token $HT_M$. Now, malicious server $M$ tries to perform an operation on another host server $O$ using $GT_M$ and $HT_M$. When $O$ performs step 2 to decrypt $HT$ with its private master key $K_{MO}$, it will not get the secret $K_{UM}$ shared between the user and the malicious host server because that was encrypted with $M$'s private master key. When $O$ tries to decrypt the rest of the message with the incorrect key obtained in step 2, it will get gibberish and the operation will fail.
