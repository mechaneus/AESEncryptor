

               ______  _____   ______                             _
         /\   |  ____|/ ____| |  ____|                           | |
        /  \  | |__  | (___   | |__   _ __   ___ _ __ _   _ _ __ | |_ ___  _ __
       / /\ \ |  __|  \___ \  |  __| | '_ \ / __| '__| | | | '_ \| __/ _ \| '__|
      / ____ \| |____ ____) | | |____| | | | (__| |  | |_| | |_) | || (_) | |
     /_/    \_\______|_____/  |______|_| |_|\___|_|   \__, | .__/ \__\___/|_|
                                                       __/ | |
                                                      |___/|_|
    by @mechaneus                                                           v 0.1

usage: AESEncryptor [-h] [-v] [-k <KEY STRING>] [-p <BINARY FILE NAME>] [-s <TEXT FILE NAME>] [-df True|False]
                    [-o <TEXT FILE NAME>]

AES payload and function name encryptor. All output will be in C/C++ variable declaration format.
```
optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -k <KEY STRING>, --encryption-key <KEY STRING>
                        The key to use for AES ecnryption. A random key will be generated if no key is provided.
  -p <BINARY FILE NAME>, --payload-file <BINARY FILE NAME>
                        The file name of a binary (.bin) payload to encrypt with AES.
  -s <TEXT FILE NAME>, --function-list-file <TEXT FILE NAME>
                        The file name of a list of strings to encrypt with AES (one per line).
  -df True|False, --decrypt-verify True|False
                        Decrypt the function list to verify the encryption. (Default: Fasle)
  -o <TEXT FILE NAME>, --output-file <TEXT FILE NAME>
                        The file name where the output will be written. WARNING: The file will be created or
                        overwritten!
```
