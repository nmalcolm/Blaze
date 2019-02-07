import nacl.utils
import os
from os.path import expanduser
from nacl.public import PrivateKey, Box
import base64
from termcolor import colored
import yaml

try:
    with open("config.yml", 'r') as ymlfile:
        cfg = yaml.safe_load(ymlfile)
except IOError:
    print(colored("Error: Failed to open config.yml. Please refer to README.md for help.", "red"))
    os._exit(0)

# We set some sensible default locations which can later be customized by the user
home = expanduser("~")
downloads_dir = home + "/Blaze"
keys_dir = home + "/.blaze"

if not cfg["directories"]["downloads"] == "":
    downloads_dir = cfg["directories"]["downloads"]

if not cfg["directories"]["keys"] == "":
    keys_dir = cfg["directories"]["keys"]

if not os.path.exists(downloads_dir):
    os.makedirs(downloads_dir)

if not os.path.exists(keys_dir):
    os.makedirs(keys_dir)

# Generate a new keypair
new_key = PrivateKey.generate()

# If a private key or public key already exists we want to be absolutely sure
# the user understands what happens if they choose to overwrite them.
if os.path.exists(keys_dir + "/private.key") or os.path.exists(keys_dir + "/public.key"):
    print(colored('==================== WARNING!!! ====================', 'red'))
    print(colored('You already have an existing keypair on this system!', 'red'))
    print(colored('By generating a new keypair you will OVERWRITE the', 'red'))
    print(colored('existing pair which could lead to the total loss', 'red'))
    print(colored('of files. Hit enter now to cancel. If you are 100%', 'red'))
    print(colored('sure you want to do this, please type "I understand"', 'red'))
    print(colored('and hit enter. YOU HAVE BEEN WARNED.', 'red'))
    print(colored('==================== WARNING!!! ====================', 'red'))
    confirm = raw_input("Confirm: ")
    
    if confirm.lower() != "i understand":
        print("Quitting.")
        os._exit(0)

# Write the public key to disk
public_key_file = open(keys_dir + "/public.key", "w")
public_key_file.write(new_key.public_key._public_key.encode('hex')) 
public_key_file.close()

# Write the private key to disk
private_key_file = open(keys_dir + "/private.key", "w")
private_key_file.write(new_key._private_key.encode('hex'))
private_key_file.close()

print(colored("Success! Your new keypair is stored here: " + keys_dir + "/", 'green'))
print(colored("PLEASE BACKUP YOUR KEYS NOW! If you lose your private key you will LOSE ACCESS TO YOUR FILES.", 'red'))
print(colored("We're all done here!", "green"))