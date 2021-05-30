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

# Generates private key and public key via RSA algorithm
def generate_rsa_keys():
    # Create private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Create public key
    public_key = private_key.public_key()
    # Convert private key to printing format
    private_key_print = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    # Convert public key to printing format
    public_key_print = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    print(private_key_print, public_key_print)


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
            generate_rsa_keys()
        if cmd_list[0] == '6':
            # TODO Create signature of the root of the tree
            print('Create signature of the root of the tree')
        if cmd_list[0] == '7':
            # TODO Valid signature
            print('Valid signature')
        command = input(">>> ")
