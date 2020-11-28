# ring_test_task_aes
Linux tool to encrypt and decrypt files using AES-256-CFB algo.

* Guesses needed action with file (encrypt/decrypt).
* Made as a typical Linux cli application (supports cli "dash" and positional arguments, relative path, 
output filename guessing).
* System endianness independent (file could be encrypted on a little-endian system and decrypted on a big-endian).
* Tested on 5gb file (md5 checksum matched after decryption and encryption, took 3:35 minutes to encrypt a file and 3.19 to decrypt with 4kb chunk size) and on a zero-length file.
![](https://i.imgur.com/7YUDv7O.png)
* Uses libgcrypt, highly popular and mostly preinstalled on all modern Linux distributions
## Build
```
$ git clone https://github.com/hatomist/ring_test_task_aes
$ cd ring_test_task_aes
$ ./build.sh  # or manually with CMake
```
The executable will be placed at ./build/ring_test_task_aes
## Usage
ring_test_task_aes [-deh] file key [out-file/path]

Encrypt or decrypt file using AES-256 encryption algorithm.

* -d              Decrypt given file
* -e              Encrypt given file (default)
* -f              Overwrite files
* -h              Show this page

Exit status:
 0  if OK, \
 1  if critical error.
 
## Example
![](https://i.imgur.com/j5LiWM4.png)
