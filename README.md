# SecureChat
SecureChat is an open source chat application with secure communication.

## How Does It Work?
### Launching
While application is being launched, it generates 2048-bit RSA key pair for client or server.
These keys are going to be used when communicating with server or client.
### Connection
When a TCP connection is established between server and client, server sends its public
key to client and expects encrypted messages from now on. Similarly, client sends its public key
to server after logging in or registering an account.
### Sending Message
When client wants to send message to another client, it requests for its public key from server.
After receiving the public key, client encrypts the message part and sends the data to server in
the following format:
```
|======================== ENCRYPTED W/ SERVER'S KEY ========================|

                                       |==== ENCRYPTED W/ RECEIVER'S KEY ===|

$sending-to  [ username of receiver ]  [ message being sent to the receiver ]
```
### Receiving Message
When server receives message being sent to a client, it forwards the data to server in the following format:
```
|======================= ENCRYPTED W/ RECEIVER'S KEY =======================|

                                       |==== ENCRYPTED W/ RECEIVER'S KEY ===|

$coming-from  [ username of sender ]   [ message being sent to the receiver ]
```
## Requirements
SecureChat uses [pycryptodome](https://pypi.org/project/pycryptodome/) library for encryption.
Therefore, this library must be installed before running the application. It can be installed
by running the following command:<br>
```
pip install pycryptodome
```
After installing pycrytodome, you can download scripts and run on your terminal.

## Command List
```
               COMMAND                  |                   DESCRIPTION
=======================================================================================
!help                                   |   Print command list.
                                        |
!register                               |   Register to server.
!login                                  |   Log in to your account.
!logout                                 |   Log out from your account.
!exit                                   |   Exit the application.
!resetkeys                              |   Regenerate RSA keys.
                                        |
@[username] [message]                   |   Send message to a user.
!file       [username]  [file_path]     |   Send file to a user
                                        |
!block      [username]                  |   Block all messages coming from a user.
!unblock    [username]                  |   Start receiving messages again from a user.
```