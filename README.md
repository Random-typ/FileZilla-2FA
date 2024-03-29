# FileZilla-2FA
This python script adds 2FA to your FileZilla FTP server.

# Setup
Run **run.bat**, make sure you have **python 3.11.2 or newer** installed.  
The first lines in the console show the available users and their 2FA status. You cannot add users through this script. You have to add them via the FTP servers Admin panel.  
You can reload the user list by typing ```reload``` and hitting enter.  
To add 2FA to a user type their name from the user list followed by ```password```.  E.g. ```FTPUser password```. Hit enter.  
After you have followed the instructions type the same user name followed by ```totp```.  E.g. ```FTPUser totp```. Hit enter. 
Now you see a QR code, you can scan it with your authenticator app of choice. E.g. Google Authenticator.  

# Login
You login with your usual credentials, but you append the password with your 2FA code from your authenticator (no spaces). 

# Bugs and issues (please read)
Currently it is not possible to change the config of the FileZilla server while the script is running, e.g. you cannot add/edit user or change any settings.

# How it works
The python script changes the password hash stored in the FileZilla configuration file every 30 seconds and tells the server to reload the configuration file.
The hash is generated by the login password appended with the 2FA code.

# Security risks
The passwords and tokens are not encrypted and stored as plain text. And there is not really a reason why they should be encrypted.  
When someone gains access to the files where passwords and tokens are stored, it does not really matter that they now have access via FTP.  
However, it would still be better if they were encrypted.  

Also after you login the 2FA code can still be used for 30 seconds or less. It does only get invalidated after a new code has been generated. 
