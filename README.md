
               ______  _____   ______                             _
         /\   |  ____|/ ____| |  ____|                           | |
        /  \  | |__  | (___   | |__   _ __   ___ _ __ _   _ _ __ | |_ ___  _ __
       / /\ \ |  __|  \___ \  |  __| | '_ \ / __| '__| | | | '_ \| __/ _ \| '__|
      / ____ \| |____ ____) | | |____| | | | (__| |  | |_| | |_) | || (_) | |
     /_/    \_\______|_____/  |______|_| |_|\___|_|   \__, | .__/ \__\___/|_|
                                                       __/ | |
                                                      |___/|_|

# A simple AES payload and function name encryptor

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
char key[] = { 0xd7, 0x11, 0x16, 0x2b, 0xa4, 0x11, 0x56, 0xd8, 0x43, 0x90, 0xaf, 0x2f, 0x71, 0xef, 0xff, 0x19 };
[!] The encrypted output in hex format is:
unsigned char sVirtualAlloc[] = { 0x81, 0x78, 0x64, 0x5f, 0xd1, 0x70, 0x3a, 0x99, 0x2f, 0xfc, 0xc0, 0x4c, 0x71 };
unsigned char sVirtualAllocEx[] = { 0x81, 0x78, 0x64, 0x5f, 0xd1, 0x70, 0x3a, 0x99, 0x2f, 0xfc, 0xc0, 0x4c, 0x34, 0x97, 0xff };
unsigned char sRtlMoveMemory[] = { 0x85, 0x65, 0x7a, 0x66, 0xcb, 0x67, 0x33, 0x95, 0x26, 0xfd, 0xc0, 0x5d, 0x8, 0xef };
unsigned char sWriteProcessMemory[] = { 0x80, 0x63, 0x7f, 0x5f, 0xc1, 0x41, 0x24, 0xb7, 0x20, 0xf5, 0xdc, 0x5c, 0x3c, 0x8a, 0x92, 0x76, 0xa5, 0x68, 0x16 };
unsigned char sNtCreateThreadEx[] = { 0x99, 0x65, 0x55, 0x59, 0xc1, 0x70, 0x22, 0xbd, 0x17, 0xf8, 0xdd, 0x4a, 0x10, 0x8b, 0xba, 0x61, 0xd7 };
unsigned char sRtlCreateUserThread[] = { 0x85, 0x65, 0x7a, 0x68, 0xd6, 0x74, 0x37, 0xac, 0x26, 0xc5, 0xdc, 0x4a, 0x3, 0xbb, 0x97, 0x6b, 0xb2, 0x70, 0x72, 0x2b };
```
