import nacl.utils
import os
from os.path import expanduser
from nacl.public import PrivateKey, Box
from optparse import OptionParser
from paramiko import SSHClient, SSHException, AuthenticationException, BadAuthenticationType
from scp import SCPClient, SCPException
from termcolor import colored
import tempfile
import yaml
import pipes
import time

try:
    with open("config.yml", 'r') as ymlfile:
        cfg = yaml.safe_load(ymlfile)
except IOError:
    print(colored("Error: Failed to open config.yml. Please refer to README.md for help.", "red"))
    os._exit(0)

ssh_info = {
    'hostname': cfg['ssh']['hostname'],
    'port': cfg['ssh']['port'],
    'username': cfg['ssh']['username'],
    'password': cfg['ssh']['password'],
    'allow_agent': False,
    'look_for_keys': False
}

# Setup the options parser
parser = OptionParser()
parser.add_option("-H", "--hash", dest="hash",
                  help="The hash of the file to download and decrypt (required).", metavar="HASH")
parser.add_option("-d", "--delete", dest="delete", action="store_true",
                  help="Delete the encrypted file from the server after downloading it (optional).")

(options, args) = parser.parse_args()

if not options.hash:
    parser.print_help()
    os._exit(0)

# We set some sensible default locations which can later be customized by the user
home = expanduser("~")
downloads_dir = home + "/Blaze"
keys_dir = home + "/.blaze"

if not cfg["directories"]["downloads"] == "":
    downloads_dir = cfg["directories"]["downloads"]

if not cfg["directories"]["keys"] == "":
    keys_dir = cfg["directories"]["keys"]

if not os.path.exists(keys_dir):
    print(colored("Keys directory does not exist! Quitting.", "red"))
    os._exit(0)

# Read and decode the public key
try:
    public_key_file = open(keys_dir + "/public.key", "r")
except IOError:
    print(colored("Error: Failed to open public key.", "red"))
    os._exit(0)

try:
    public_key = public_key_file.readline().decode('hex')
except TypeError:
    print(colored("Error: Could not decode public key!", "red"))
    os._exit(0)

public_key_file.close()

# Read and decode the private key
try:
    private_key_file = open(keys_dir + "/private.key", "r")
except IOError:
    print(colored("Error: Failed to open private key.", "red"))
    os._exit(0)

try:
    private_key = private_key_file.readline().decode('hex')
except TypeError:
    print(colored("Error: Could not decode private key!", "red"))
    os._exit(0)

private_key_file.close()

try:
    decoded_public_key = nacl.public.PublicKey(public_key)
except nacl.exceptions.CryptoError:
    print(colored("Error: Could not load public key. It may be corrupt or invalid.", "red"))
    os._exit(0)

try:
    decoded_private_key = nacl.public.PrivateKey(private_key)
except nacl.exceptions.CryptoError:
    print(colored("Error: Could not load private key. It may be corrupt or invalid.", "red"))
    os._exit(0)

bb = Box(decoded_private_key, decoded_public_key)

ssh = SSHClient()
ssh.load_system_host_keys()

try:
    ssh.connect(**ssh_info)
except BadAuthenticationType:
    print(colored("Error: Server doesn't support this authentication type.", "red"))
    os._exit(0)
except AuthenticationException:
    print(colored("Error: Authentication failed. Please check the credentials.", "red"))
    os._exit(0)

# SCPCLient takes a paramiko transport as an argument
scp = SCPClient(ssh.get_transport())

print(colored("Downloading file...", "green"))

# Download the encrypted file and save it to disk
try:
    scp.get(cfg["ssh"]["directory"] + "/" + options.hash, tempfile.gettempdir() + "/blaze_d_" + options.hash)
except SCPException, e:
    print(colored("Error: " + str(e), "red"))
    os._exit(0)

scp.close()

print(colored("Reading file...", "green"))

encrypted_file = open(tempfile.gettempdir() + "/blaze_d_" + options.hash, "r")
encrypted = encrypted_file.read()
encrypted_file.close()

print(colored("Decrypting file...", "green"))

try:
    decoded_filename = options.hash.decode("hex")
except TypeError:
    print(colored("Error: Unable to decode filename", "red"))
    decoded_filename = "corrupt"

try:
    plaintext_filename = bb.decrypt(decoded_filename)
except nacl.exceptions.CryptoError:
    print(colored("Error: Unable to decrypt filename, attempting to decrypt file anyway", "red"))
    plaintext_filename = "blaze_unknown_file_" + str(int(time.time()))

try:
    plaintext = bb.decrypt(encrypted)
except nacl.exceptions.CryptoError:
    print(colored("Error: Unable to decrypt file", "red"))
    os._exit(0)

print(colored("Decrypted '" +  plaintext_filename + "'", "green"))

print(colored("Saving to " + downloads_dir + "/" + plaintext_filename, "green"))

# Ask the user if they wish to overwrite the file if it already exists
if os.path.exists(downloads_dir + "/" + plaintext_filename):
    confirm = raw_input("The file '" + downloads_dir + "/" + plaintext_filename + "' already exists. Do you want to overwrite it? y/N: ")
    
    if confirm.lower() != "y":
        print("File already exists, skipping.")
        os._exit(0)

# Save the decrypted file to disk
decrypted_file = open(downloads_dir + "/" + plaintext_filename, "w")
decrypted_file.write(plaintext)
decrypted_file.close()

# If the user wants to delete the file from the server we simply run `rm -rf` on it.
# TODO: Does `pipes.quote()` provide enough protection against command injection?
if options.delete:
    print("Deleting file from server...")

    try:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("rm -rf " + pipes.quote(cfg["ssh"]["directory"] + "/" + options.hash))
    except SSHException:
        print(colored("There was an error connecting to the remote server. File may still exist on the server.", "red"))
        ssh.close()

# Remove the temporary file from disk
os.remove(tempfile.gettempdir() + "/blaze_d_" + options.hash)

print(colored("We're all done here!", "green"))