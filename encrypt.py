import nacl.utils
import os
from os.path import expanduser
from nacl.public import PrivateKey, Box
from optparse import OptionParser
from paramiko import SSHClient, SSHException, AuthenticationException, BadAuthenticationType
import paramiko
from scp import SCPClient
from termcolor import colored
from tempfile import mkstemp
import yaml

try:
    with open("config.yml", 'r') as ymlfile:
        cfg = yaml.safe_load(ymlfile)
except IOError:
    print(colored("Error: Failed to open config.yml. Please refer to README.md for help.", "red"))
    os._exit(0)

timeout = 600
if "timeout" in cfg['ssh']:
    timeout = cfg['ssh']['timeout']

auth = "password"
if "auth" in cfg['ssh']:
    auth = cfg['ssh']['auth']

if auth == "private_key":
    if not "private_key" in cfg['ssh']:
        print(colored("Error: No SSH private key specified in config.yml", "red"))
        os._exit(0)

    private_key_path = expanduser(cfg['ssh']['private_key'])

    try:
        ssh_private_key = open(private_key_path, "r")
    except IOError:
        print(colored("Error: Failed to open SSH private key.", "red"))
        os._exit(0)

    pkey = paramiko.RSAKey.from_private_key_file(private_key_path)

    ssh_info = {
        'hostname': cfg['ssh']['hostname'],
        'port': cfg['ssh']['port'],
        'username': cfg['ssh']['username'],
        'pkey': pkey,
        'allow_agent': False,
        'look_for_keys': False
    }
else:
    if not "password" in cfg['ssh']:
        print(colored("Error: No SSH password specified in config.yml", "red"))
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
parser.add_option("-f", "--file", dest="file",
                  help="The file to encrypt (required).", metavar="FILE")

(options, args) = parser.parse_args()

if not options.file:
    parser.print_help()
    os._exit(0)

if not os.path.exists(options.file):
    print(colored("File does not exist!", "red"))
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

print(colored("Reading file...", "green"))

try:
    filea = open(options.file, "r")
except IOError:
    print(colored("Error: Unable to open file for encryption. Do you have read access to this file?", "red"))
    os._exit(0)

file_contents = filea.read()
filea.close()

print(colored("Encrypting file...", "green"))

try:
    encrypted_filename = bb.encrypt(os.path.basename(options.file))
except nacl.exceptions.CryptoError:
    print(colored("Error: Unable to encrypt the filename!", "red"))
    os._exit(0)

try:
    encrypted = bb.encrypt(file_contents)
except nacl.exceptions.CryptoError:
    print(colored("Error: Unable to encrypt file!", "red"))
    os._exit(0)

fd, temp_path = mkstemp()

encrypted_file = open(temp_path, "w")
encrypted_file.write(encrypted) 
encrypted_file.close()
os.close(fd)

print(colored("Successfully encrypted! Uploading...", "green"))

ssh = SSHClient()
ssh.load_system_host_keys()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    ssh.connect(**ssh_info)
except BadAuthenticationType:
    print(colored("Error: Server doesn't support this authentication type.", "red"))
    os._exit(0)
except AuthenticationException:
    print(colored("Error: Authentication failed. Please check the credentials.", "red"))
    os._exit(0)

# SCPCLient takes a paramiko transport as an argument
scp = SCPClient(ssh.get_transport(), socket_timeout=timeout)

scp.put(temp_path, remote_path=cfg["ssh"]["directory"] + '/' + encrypted_filename.encode("hex"))

scp.close()

# Remove the temporary file from disk
os.remove(temp_path)

print(colored("Done! Hash: " + encrypted_filename.encode("hex"), "green"))