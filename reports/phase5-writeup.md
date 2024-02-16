
# CS 1653 Term Project Phase 5 Writeup

### Group Information

Name | Email | Github
---|---|---
Wuyue Liu | wul5@pitt.edu | Lucaserlw
Jakob Ross | jjr113@pitt.edu | jjr113
Sean Lord | sal244@pitt.edu | LordOfBeans

## Threat Model - DoS Attack

Assume our system only covers threats T1 through T7. We are fairly confident that an adversary cannot read encrypted messages, impersonate other users, get leaked information from host servers, and perform message operations as other users, among other things. One of the vulnerabilities we're not covering in this system is the potential for an attacker to take down a host server through the use of a Denial of Service (DoS) attack. While we can assume that the authentication server has a substantial number of resouces and its operations are limited enough that it will not be vulnrable to DoS attacks, the same cannot be said for host servers.

Since we have a distributed system, host servers can be created by anyone and run on virtually any machine. In a fairly widespread distributed system, it will likely occur that people will develop grudges or feel anger towards specific servers. Maybe that server tends to host people with certain political opinions or that host server sees substantial used by government officials. There are many reasons and adversary may want to have a server put offline. As such, we must minimize the potential for a host server to be put offline.

## Method of Attack

The easiest way for an adversary to put a host server offline is to exploit a resource imbalance in writing and reading messages. While it doesn't take much effort for an adverary to request to read messages, a system may have to put immense effort into sending all of the messages in a server. It will not only have to read all of the message files, but also collect them and send them to the adversary in a large message.

An attack might look something like this, where $A$ is the adversary and $H$ is the host server:
1. $A \rightarrow H$: Write 4kB message to channel $C$
3. $A$: Repeat step 1 over and over again for a while.
4. $A \rightarrow H$: Read all of the messages in channel $C$
5. $A$: Ignore response from $H$.
6. $A$: Repeat steps 4 and 5 over and over again for a while.

Why might this work? This will work because the adversary can fill up channel $C$ with a bunch of messages and then force host server $H$ to send all of them quickly in succession. This is problematic because reading all of those message files takes a long time and sending them over the network takes an even longer time. As long as the adversary establishes multiple connections in multiple threads, this could very quickly eat up all of server's resouces with very limited effort from the adversary.

## Countermeasure

#### Chosen Mechanism

In order to combat DoS (Denial of Service) and DDoS (Distributed Denial of Service) attacks, our strategy involves implementing a proof-of-work mechanism, specifically a computational puzzle, to balance out the resouce disparity between clients and host servers. When a user tries to perform any of the host server's channel or messaging operations, they will be prompted to solve a challenging and time-consuming puzzle before gaining access. This puzzle can be quickly generated on the server side and does not require significant data storage. By introducing this puzzle, we can effectively reduce the rate at which an attacker can send connection attempts, resulting in a significant mitigation of DoS attacks.

The protocol is shown below:
$U$ refers to the client and $S$ refers to the host sever.
1. $U \rightarrow S$: Request a channel or messaging operation
2. $S$: Generate a 64-bit bit string $m$
3. $S \rightarrow U$: $m, b$ where b is number of 0-bits (typically 20)
4. $U$: Find 8-byte $n$ such that $H(m||n)$ begins with $b$ 0-bits
5. $U \rightarrow S$: Send $n$
6. $S$: verify that $H(m||n)$ begins with $b$ 0-bits

#### Argument

This method works for preventing the attack above because it forces the adversary to perform additional work that make the attack above far more resource-consuming. Since the adversary needs to find a hash that leads with 20 0-bits before they can proceed with any operation in the host server, it will require far more time and resource to launch a substantial attack. Finding a hash that begins with 20 zero-bits can take updwards of a second so the adversary will have a difficult time really overwhelming even a fairly weak host server.
