###########################################
# AES payload and function name encryptor #
# By @mechaneus                           #
###########################################

import sys
from os import urandom
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib
import argparse
import codecs

__version__ = '0.1'

# Function that prints the help message.
def usage():
    print("Usage:")
    print("Encrypt function list: %s -fl <function list filename>" % sys.argv[0])
    print("Encrypt payload: %s -pf <raw payload file>" % sys.argv[0])
    print("Encrypt string list: %s -s <string list filename>" % sys.argv[0])

# Take a file with a payload in bytes .bin format, encrypt it and print the result in C variable declaration format.
def encryptPayload(payloadFilename, KEY):
    print("[!] Encrypting payload...")

    # Read the binary payload from the file, in bytes.
    try:
        payloadFileItem = open(payloadFilename, "rb").read()     
    except Exception as error:
        # Print error if anything goes wrong with the file operation.
        print(f"[X] Error opening file {payloadFilename}!", error)
        sys.exit()

    # If the file is ok, encrypt the payload.
    try:
        # Generate a simple IV
        iv = 16 * b'\x00'
        # Create an AES cipher object
        cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)    
        encryptedPayloadFileItem = cipher.encrypt(pad(payloadFileItem, AES.block_size))
        # Store the output in C variable assignment format.
        encryptedPayloadOutput = 'unsigned char payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in encryptedPayloadFileItem) + ' };'
        return encryptedPayloadOutput
    except Exception as error:
        # Print error if anything goes wrong with the encryption operation.
        print("[X] encryptPayload: An exception occurred:", error)
        sys.exit()        


# Take a file with a list of strings, encrypt it and print the result.
def encryptFunctionList(stringListFilename, KEY, decryptVerify):
    print("[!] Encrypting function list...")
    
    # Read the string list from the file, in a strings' array, one per line.
    try:
        encryptedListOutput = ""
        stringList = open(stringListFilename, "r").read().splitlines()
    except Exception as error:
        # Print error if anything goes wrong with the file operation.
        print(f"[X] Error opening file {stringListFilename}!", error)
        sys.exit()
        
    # If the file is ok, traverse it.
    for stringItem in stringList:      
        try:        
            stringItem +="\x00"
            # Generate a simple IV
            iv = 16 * b'\x00'
            # Create an AES cipher object
            cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)
            # Encrypt each string (one per line).
            encryptedStringItem = cipher.encrypt(pad(bytes(stringItem, encoding='utf-8'), AES.block_size))
            
            # If decryption verification is enabled, decrypt all strings and print them in byte format.
            if decryptVerify == True or decryptVerify == "true":
                iv = 16 * b'\x00'
                decrypt_cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)
                plain_text = decrypt_cipher.decrypt(encryptedStringItem)
                print(f"Original string: {bytes(stringItem, encoding='utf-8')}")
                print(f"Decrypted string: {stringItem}: {plain_text}")            

        except Exception as error:
            # Print error if anything goes wrong with the encryption operation.
            print("[X] encryptFunctionList: An exception occurred:", error)
            sys.exit()
        # Store the output in C variable assignment format.
        encryptedListOutput += f'unsigned char s{stringItem}[] = {{ 0x' + ', 0x'.join(hex(x)[2:] for x in encryptedStringItem) + ' };\n'       
        
    return encryptedListOutput

globalKEY = ""
# Check if a key was provided. If not, generate a random key.
def manageKey(KEY):
    if KEY:
        KEY = arguments.KEY.encode('utf-8')
        print(f"[!] The plaintext key provided is: {KEY.decode('utf-8')}")      
    else:
        # Two ways to get a random key
        KEY = get_random_bytes(16)
        print(f"[!] A random key of non-printable characters was generated.")
    return KEY
    

def main():
    print(f"""       
               ______  _____   ______                             _             
         /\   |  ____|/ ____| |  ____|                           | |            
        /  \  | |__  | (___   | |__   _ __   ___ _ __ _   _ _ __ | |_ ___  _ __ 
       / /\ \ |  __|  \___ \  |  __| | '_ \ / __| '__| | | | '_ \| __/ _ \| '__|
      / ____ \| |____ ____) | | |____| | | | (__| |  | |_| | |_) | || (_) | |   
     /_/    \_\______|_____/  |______|_| |_|\___|_|   \__, | .__/ \__\___/|_|   
                                                       __/ | |                  
                                                      |___/|_|                  
    by @mechaneus                                                           v {__version__}
    """)

    # Parse script arguments
    parser = argparse.ArgumentParser(prog='AESEncryptor', description='AES payload and function name encryptor. All output will be in C/C++ variable declaration format.', conflict_handler='resolve')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + __version__)
    parser.add_argument('-k', '--encryption-key', dest='KEY', metavar='<KEY STRING>', help='The key to use for AES ecnryption. A random key will be generated if no key is provided.')
    parser.add_argument('-p', '--payload-file', dest='payloadFilename', metavar='<BINARY FILE NAME>', help='The file name of a binary (.bin) payload to encrypt with AES.')
    parser.add_argument('-s', '--function-list-file', dest='stringListFilename', metavar='<TEXT FILE NAME>', help='The file name of a list of strings to encrypt with AES (one per line).')
    parser.add_argument('-df', '--decrypt-verify', dest='decryptVerify', metavar='True|False', choices=['True','true','False','false'], default='False', help='Decrypt the function list to verify the encryption. (Default: Fasle)')
    parser.add_argument('-o', '--output-file', dest='outputFilename', metavar='<TEXT FILE NAME>', help='The file name where the output will be written. WARNING: The file will be created or overwritten!')
    arguments = parser.parse_args()
    
    # Check if any argument was provided. If not, print help.
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(0)

    # Check which parameters were provided and execute the corresponding actions.
    if arguments.payloadFilename:
        globalKEY = manageKey(arguments.KEY)
        encryptedOutput = encryptPayload(arguments.payloadFilename, globalKEY)
    elif arguments.stringListFilename:
        globalKEY = manageKey(arguments.KEY)
        encryptedOutput = encryptFunctionList(arguments.stringListFilename, globalKEY, arguments.decryptVerify)
    else:
        parser.print_help(sys.stderr)
        sys.exit(0) 
   
    # If an output file was provided then write the output in the file, otherwise print it on the console.
    if arguments.outputFilename and encryptedOutput:
        print("[!] Writing output to file... (All output will be in C/C++ variable declaration format.)")
        keyOutput = 'char key[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in globalKEY) + ' };\n' # Store the key string in C variable assignment format.
        try:       
            open(arguments.outputFilename, "w").write(keyOutput)
            open(arguments.outputFilename, "a").write(encryptedOutput)
        except Exception as error:
            print("[X] Writing output to file: An exception occurred:", error)
        print("[!] Done!")
    elif encryptedOutput:
        print(f"[!] The key in hex format is:")
        print('char key[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in globalKEY) + ' };') 
        print(f"[!] The encrypted output in hex format is:")
        print(encryptedOutput)
    else:
        print("[X] Output error.")


if __name__ == '__main__':
    main()
