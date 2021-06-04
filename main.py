# TODO Add shilo ID
# Shilo Lieopold ?????, Yonatan Gat 203625264

import hashlib
import math
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class MerkleTree:
    def __init__(self):
        self.root = None
        self.leaves = []
        self.num_of_leaves = 0
        self.depth = 0


    def insert_leaf(self, leaf_value):
        # Create leaf
        new_leaf = MerkleTreeNode(leaf_value)
        self.leaves.append(new_leaf)
        if self.num_of_leaves > 0:
            self.depth = math.ceil(math.log2(self.num_of_leaves))
        self.num_of_leaves += 1
        # Now we need to found the place of the leaf in the tree
        # and update all hash_values in the tree

        # First leaf
        if self.root is None:
            self.root = new_leaf
        # Not first leaf
        else:
            leaf_num = self.num_of_leaves - 1
            # Check if leaf_num is odd or even
            # leaf_num is even - we need to add a new level to the tree
            if leaf_num % 2 == 0:
                # Check if the tree is full
                if (2 ** self.depth) == self.num_of_leaves - 1:
                    # Create new root
                    new_root = MerkleTreeNode(self.root.hash_value + new_leaf.hash_value)
                    new_root.left = self.root
                    self.root.father = new_root
                    new_root.right = new_leaf
                    # Update root
                    self.root = new_root
                    new_leaf.father = self.root
                # Tree is not full
                else:
                    # Get the previous leaf
                    prev_leaf = self.leaves[self.num_of_leaves - 2]
                    # Get the father of the previous leaf
                    old_father = prev_leaf.father
                    new_father = MerkleTreeNode(old_father.hash_value + new_leaf.hash_value)
                    new_father.father = old_father.father
                    old_father.father.right = new_father
                    new_father.left = old_father
                    old_father.father = new_father
                    new_father.right = new_leaf
                    new_leaf.father = new_father
                    # Update hash value until the root
                    self.update_hash_values(new_father)
            # leaf_num is odd - replace the old right leaf in the new leaf
            # and update the internal nodes
            else:
                # Get the previous leaf
                prev_leaf = self.leaves[self.num_of_leaves - 2]
                # Create new node to be the father of the new leaf and the previous leaf
                father = MerkleTreeNode(prev_leaf.hash_value + new_leaf.hash_value)
                father.father = prev_leaf.father
                father.left = prev_leaf
                prev_leaf.father = father
                father.right = new_leaf
                new_leaf.father = father
                # In case of the second leaf
                if self.root == prev_leaf:
                    self.root = father
                else:
                    father.father.right = father
                    self.update_hash_values(father)

    def update_hash_values(self, node):
        curr = node
        # Iterate and update until the root
        while curr != self.root:
            father = curr.father
            father.value = father.left.hash_value + father.right.hash_value
            father.hash_value = encrypt_string(father.value)
            curr = father





class MerkleTreeNode:
    def __init__(self, value):
        self.value = value
        self.hash_value = encrypt_string(self.value)
        self.right = None
        self.left = None
        self.father = None


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


def sign_on_massage(key):
    root = encrypt_string("aaa")
    b = bytes(root, 'utf-8')
    signature = key.sign(
        b,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print(str(signature))


def signature_verification(public_key, signature, message):
    if(public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )):
        print("True")
    else:
        print("False")


if __name__ == '__main__':
    merkle_tree = None
    print('Welcome!')
    print('Type \'quit\' to close the app')
    command = input(">>> ")
    while command != 'exit':
        cmd_list = command.split()
        if len(cmd_list) == 0:
            command = input(">>> ")
            continue
        if cmd_list[0] == '1':
            # Create tree at the first time
            if merkle_tree is None:
                merkle_tree = MerkleTree()
            # Add the leaf to the tree
            merkle_tree.insert_leaf(cmd_list[1])
        if cmd_list[0] == '2':
            # Print the root of the tree
            if merkle_tree is not None:
                print(merkle_tree.root.hash_value)
            else:
                print("")
        if cmd_list[0] == '3':
            # TODO Create Proof of inclusion
            print('Create Proof oc inclusion')
        if cmd_list[0] == '4':
            # TODO Check Proof of inclusion
            print('Check Proof oc inclusion')
        if cmd_list[0] == '5':
            generate_rsa_keys()
        if cmd_list[0] == '6':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            # Create public key
            public_key = private_key.public_key()
            sign_on_massage(private_key)
        if cmd_list[0] == '7':
            # TODO Valid signature
            signature_verification(cmd_list[1], cmd_list[2], cmd_list[3])
        command = input(">>> ")
