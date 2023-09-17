

               ______  _____   ______                             _
         /\   |  ____|/ ____| |  ____|                           | |
        /  \  | |__  | (___   | |__   _ __   ___ _ __ _   _ _ __ | |_ ___  _ __
       / /\ \ |  __|  \___ \  |  __| | '_ \ / __| '__| | | | '_ \| __/ _ \| '__|
      / ____ \| |____ ____) | | |____| | | | (__| |  | |_| | |_) | || (_) | |
     /_/    \_\______|_____/  |______|_| |_|\___|_|   \__, | .__/ \__\___/|_|
                                                       __/ | |
                                                      |___/|_|

# AES payload and function name encryptor

**All output will be in C/C++ variable declaration format.**
## Usage
```
AESEncryptor.py [-h] [-v] [-k <KEY STRING>] [-p <BINARY FILE NAME>] [-s <TEXT FILE NAME>] [-df True|False]
                    [-o <TEXT FILE NAME>]

Arguments:
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

## Sample Funcion list file
```
VirtualAlloc
VirtualAllocEx
RtlMoveMemory
WriteProcessMemory
NtCreateThreadEx
RtlCreateUserThread
```

## Sample output
```
[!] A random key of non-printable characters was generated.
[!] Encrypting function list...
[!] The key in hex format is:
char key[] = { 0xc4, 0x72, 0x9b, 0x84, 0x6, 0x77, 0x88, 0x83, 0x75, 0xe0, 0x5e, 0x5d, 0xd8, 0x71, 0x96, 0x8a };
[!] The encrypted output in hex format is:
unsigned char sVirtualAlloc [] = { 0x1, 0x4b, 0x4a, 0xd6, 0x43, 0xea, 0x30, 0xe6, 0x2a, 0x7b, 0x5f, 0xd9, 0x91, 0x1b, 0xa8, 0x20 };
unsigned char sVirtualAllocEx [] = { 0x8d, 0xf6, 0xc1, 0xfd, 0xb2, 0xcb, 0xed, 0x75, 0x6c, 0x40, 0xdf, 0xbd, 0x79, 0x79, 0x34, 0xd5 };
unsigned char sRtlMoveMemory [] = { 0xed, 0x99, 0xaf, 0x7d, 0x85, 0xd9, 0x8, 0xdb, 0xc9, 0xc6, 0xcd, 0xf4, 0xbc, 0x95, 0xce, 0x9c };
unsigned char sWriteProcessMemory [] = { 0xca, 0xb3, 0xc8, 0x9a, 0x58, 0xa9, 0x85, 0xe1, 0x10, 0x98, 0xf0, 0xc0, 0x54, 0xca, 0xb3, 0xf1, 0xb6, 0x18, 0xe8, 0x9b, 0xda, 0xbd, 0x52, 0xef, 0xa2, 0x5f, 0x57, 0x5f, 0xc6, 0x62, 0xc0, 0x6e };
unsigned char sNtCreateThreadEx [] = { 0x2d, 0x40, 0x57, 0xd9, 0xd6, 0x72, 0x44, 0xe6, 0x7b, 0xa5, 0x71, 0x59, 0xf8, 0x19, 0x25, 0x82, 0x94, 0x14, 0xc5, 0xfb, 0xf2, 0xe7, 0xd1, 0xde, 0x83, 0xca, 0x8c, 0x37, 0x82, 0x52, 0xe1, 0x98 };
unsigned char sRtlCreateUserThread [] = { 0xa3, 0x94, 0xaf, 0x43, 0x4, 0xf, 0x7b, 0x3d, 0x9, 0xa3, 0x31, 0x48, 0x4e, 0x6e, 0xf9, 0x24, 0x23, 0xab, 0xf, 0x5, 0xff, 0xdd, 0x74, 0xdc, 0xcc, 0x84, 0x80, 0x63, 0x28, 0xcb, 0x8a, 0xf5 };
```
