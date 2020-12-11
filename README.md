# SecureChat
SecureChat is an open source chat application with secure communication.

## Installation
SecureChat uses [pycryptodome](https://pypi.org/project/pycryptodome/) library for encryption. Therefore, this library must be installed before running the application. It can be installed by running the following command:<br>
```
pip install pycryptodome
```
After installing pycrytodome, you can download scripts and run on your terminal.

## Command List
```
          COMMAND           |                    DESCRIPTION
===============================================================================
!help                       |      Prints command list.
                            |
!register                   |      Register to server.
!login                      |      Log in to your account.
!logout                     |      Log out from your account.
!exit                       |      Exits the application.
                            |
@[username] [message]       |      Send message to a user.
                            |
!block      [username]      |      Blocks all messages coming from a user.
!unblock    [username]      |      Starts receiving messages again from a user.
```