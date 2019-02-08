# Blaze

Blaze is a tool for encrypting files and storing them on a remote server. Currently only SSH is supported but other data stores and transport protocols may be introduced in the future.

## Security

Blaze uses the Python library `PyNaCl` which is a binding to libsodium. All encryption and decryption is done on your machine. File names are encrypted too. Bear in mind the encrypted file will only be 40 bytes larger in size than the original file.

This project has not recieved a security audit and vulnerabilities will exist. Do not use this project as a single backup solution. I am not responsible for data loss.

## Setup

Requirements:

- A non-Windows computer (send a pull request if you require Windows support)
- A server (VPS, Raspberry Pi, supercomputer, etc) that you can SSH into
- Python 2.7

```
$ git clone https://github.com/nmalcolm/Blaze
$ cd Blaze
$ pip install -r requirements.txt
$ mv config.yml.example config.yml
$ nano config.yml # Add your SSH details
```

## Usage

Generate a new public/private keypair:

```
$ python generate_keys.py
Success! Your new keypair is stored here: /Users/nathan/.blaze/
PLEASE BACKUP YOUR KEYS NOW! If you lose your private key you will LOSE ACCESS TO YOUR FILES.
We're all done here!
```

At this point you should absolutely make a backup of your keys.

Encrypt a file and upload it:

```
$ python encrypt.py -f ~/Downloads/bankdetails.txt
Reading file...
Encrypting file...
Successfully encrypted! Uploading...
Done! Hash: 39d2a4ba24c201f67f595af14570939de63b22b561633f0fb3856106223c384ef68edda00cd509834d386722e010b90c900db471314ac0
```

List encrypted files on the remote server:

```
$ python list_files.py
Listing encrypted files and decrypting their filenames...
File: bankdetails.txt (36.0B), Hash: 39d2a4ba24c201f67f595af14570939de63b22b561633f0fb3856106223c384ef68edda00cd509834d386722e010b90c900db471314ac0
We're all done here!
```

Download and decrypt a file from the remote server:

```
$ python decrypt.py -H 39d2a4ba24c201f67f595af14570939de63b22b561633f0fb3856106223c384ef68edda00cd509834d386722e010b90c900db471314ac0
Downloading file...
Reading file...
Decrypting file...
Decrypted 'bankdetails.txt'
Saving to /Users/nathan/Blaze/bankdetails.txt
We're all done here!
```

## Future Features

- Support for encrypting multiple files at once, including directories
