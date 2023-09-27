import json
import pyotp
import hashlib
import base64
from lxml import etree
#from xml.etree.ElementTree import ElementTree
import sched
import time
import os
import secrets
import string
import qrcode
from io import StringIO
from PIL import Image
import sys
f
def getHash(_password, _salt, _iterations = 100000):
    return base64.b64encode(hashlib.pbkdf2_hmac(
    'SHA256',
    _password.encode('utf-8'),
    _salt.encode('utf-8'),
    _iterations
    ))

def userHas2FAEnabled(_user):
    for user in config["users"]:
        if _user.get("name") == user["name"]:
            return user["2FAEnabled"]
    return False

def userIsNotInConfig(_user):
    for user in config["users"]:
        if _user.get("name") == user["name"]:
            return False
    return True

def loadUsers():
    for child in root.findall('d:user', ns):
        if userIsNotInConfig(child):
            config["users"].append({
            "name": child.get("name"),
            "2FAEnabled": False
            })

def UpdateFTPServer():
    return
    os.system("SC control filezilla-server paramchange")# makes the ftp server reload its config

def updatePasswords(_scheduler):
    #_scheduler.enter(30, 1, updatePasswords, (_scheduler,))#start next check in 30 seconds
    for user in config["users"]:
        if user["2FAEnabled"] == True:
            for child in root.findall('d:user', ns):
                if child.get("name") == user["name"]:
                    totp = pyotp.TOTP(user["token"])
                    child.find("d:password", ns).find("d:hash", ns).text = getHash(user["password"] + totp.now(), child.find("d:password", ns).find("d:salt", ns).text).decode("utf8")
    etree.(config)
    #with open('users.xml', 'wb') as f:
    #f2 = StringIO()
    #etree.ElementTree(root).write_c14n(f2)
    #tree.write_c14n(f2.buffer)
    f = open('users.xml', 'wb')
    #tree.getroot().addprevious(etree.ProcessingInstruction('xml', 'version=1.0'))
    f.write(f2.getvalue())
    f.close()
        #ElementTree(root).write(f, encoding="utf-8", xml_declaration=True, default_namespace=None, method='xml', short_empty_elements=False)
    UpdateFTPServer()



configFile = open("config.json")
config = json.loads(configFile.read())
configFile.close()

#lxml.register_namespace('', "https://filezilla-project.org")
tree = etree.parse(r'users.xml')
#tree.register_namespace('', "https://filezilla-project.org")
root = tree.getroot()
ns = {"d": "https://filezilla-project.org"}
loadUsers()

# run updatePasswords every 30 seconds
scheduler = sched.scheduler(time.time, time.sleep)
scheduler.enter(3, 1, updatePasswords, (scheduler,))
scheduler.run()



while True:
    with open("config.json", "w") as outfile:
        json.dump(config, outfile)
    os.system("cls")# os specific. I dont like that
    print("Users:")
    for user in config["users"]:
        print(user["name"], " 2FA enabled: ", user["2FAEnabled"])
    print("type: username password  | Enable user and set password")
    print("type: username disable   | Disable user")
    print("type: username enable    | Enable user")
    print("type: username totp      | Prints QR code to scan with TOTP app (e.g. Google Authenticator)")
    command = input(">")
    args = command.split(' ')
    if len(args) < 2:
        continue
    for user in config["users"]:
        if user["name"] == args[0]:
            if args[1] == "password":
                password = input("Enter password (leave empty to generate password(recommended)):")
                alphabet = string.ascii_letters + string.digits
                if len(password) == 0:#generate password
                    password = ''.join(secrets.choice(alphabet) for i in range(20))
                    print("Generated secure password: " + password)
                if user.get("token") is None:#set token
                    user["token"] = pyotp.random_base32()
                user["password"] = password
                user["2FAEnabled"] = True
                print("Password set!")
                input("Press enter to continue")
                continue
            if args[1] == "disable":
                user["2FAEnabled"] = False
                input("Press enter to continue")
                continue
            if args[1] == "enable":
                user["2FAEnabled"] = True
                input("Press enter to continue")
                continue
            if args[1] == "totp":
                if user.get("token") is None:#set token
                    user["token"] = pyotp.random_base32()
                qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=1,# pixels per box
                border=2,#border thickness
                )
                totp = pyotp.totp.TOTP(user["token"]).provisioning_uri(name=f'FTP: {user["name"]}', issuer_name='ftp.retard.inc.com')
                qr.add_data(totp)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                pixels = list(img.getdata())
                width = img.size[0]
                asciiImg = []
                for i, p in enumerate(pixels):
                    if pixels[i] < 100:
                        asciiImg.append("  ")
                    else:
                        asciiImg.append("##")
                    if (i + 1) % width == 0:
                        asciiImg.append("\n")
                sys.stdout.write(''.join(asciiImg))
                print("otpauth:" + totp)
                input("Press enter to continue")
                continue
            



#salt = base64.b64decode("xWNPODqgmPmkMfeYn6Kz6FmRggpYDMFWVusqirQvvcg=")
#password = "G2tEY659X5e6bZ"
#print(getHash(password, salt).decode('utf-8'))






#with open("config.json", "w") as outfile:
#    json.dump(config, outfile)


#totp = pyotp.TOTP('base32secret3232')
#totp.now()
