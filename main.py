# TODO Add shilo ID
# Shilo Lieopold ?????, Yonatan Gat 203625264

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509


# Generate symmetric key
# key = Fernet.generate_key()

# Get string and return sha256 of the string
def encrypt_string(str_input):
    return hashlib.sha256(str_input.encode()).hexdigest()


if __name__ == '__main__':
    print('Welcome!')
    print('Type \'quit\' to close the app')
    command = input(">>> ")
    while command != 'exit':
        cmd_list = command.split()
        if cmd_list[0] == '1':
            # TODO Add leaf to the tree
            print('add leaf')
        if cmd_list[0] == '2':
            # TODO Calculate the root of the tree
            print('Calculate the root of the tree')
        if cmd_list[0] == '3':
            # TODO Create Proof of inclusion
            print('Create Proof oc inclusion')
        if cmd_list[0] == '4':
            # TODO Check Proof of inclusion
            print('Check Proof oc inclusion')
        if cmd_list[0] == '5':
            # TODO Create private key and public key with RSA
            print('Create private key and public key with RSA')
        if cmd_list[0] == '6':
            # TODO Create signature of the root of the tree
            print('Create signature of the root of the tree')
        if cmd_list[0] == '7':
            # TODO Valid signature
            print('Valid signature')
        command = input(">>> ")
