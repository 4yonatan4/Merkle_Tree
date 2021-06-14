# Shilo Leopold 304996937, Yonatan Gat 203625264
import base64
import hashlib
import math
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
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


def sign_on_massage(key, root):
    while True:
        arr_in = input()
        if arr_in:
            key.append(arr_in)
        else:
            break
    str_key = '\n'.join(key)
    en_key = bytes(str_key, 'utf-8')
    en_root = root.encode()
    key1 = load_pem_private_key(en_key, password=None)
    signature = key1.sign(
        en_root,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print(base64.b64encode(signature).decode())


def signature_verification(public_key):
    while True:
        arr_in = input()
        if arr_in:
            public_key.append(arr_in)
        else:
            break
    temp = public_key.pop()
    a = temp.split()
    end_pub = a[0] + " " + a[1] + " " + a[2]
    public_key.append(end_pub)
    key_str = '\n'.join(public_key)
    en_key = bytes(key_str, 'utf-8')
    p_key = load_pem_public_key(en_key)
    signature = a[3]
    mes = a[4]
    dec_sig = base64.decodebytes(signature.encode())
    message = mes.encode()
    try:
        p_key.verify(
            dec_sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("True")
    except:
        print("False")


# Print Proof Of Inclusion of the current tree and specific leaf
def proof_of_inclusion(merkle_tree, leaf_num):
    if merkle_tree is None or merkle_tree.num_of_leaves == 0 \
            or leaf_num >= merkle_tree.num_of_leaves or leaf_num < 0:
        print("")
        return
    # Add the root of the tree
    hash_list = [merkle_tree.root.hash_value]
    # In case of just one node
    if merkle_tree.num_of_leaves == 1:
        print(*hash_list)
        return
    # Now we need to go up until the root and take one node from every level
    curr = merkle_tree.leaves[leaf_num]
    while curr != merkle_tree.root:
        father = curr.father
        # Check if curr is right or left child
        if father.right == curr:
            hash_list.append("0" + father.left.hash_value)
        else:
            hash_list.append("1" + father.right.hash_value)
        curr = father
    print(*hash_list)


def check_proof_of_inclusion(leaf_value, root, hash_list):
    res = encrypt_string(leaf_value)
    for i in hash_list:
        if i[0] == '0':
            res = encrypt_string(i[1:] + res)
        else:
            res = encrypt_string(res + i[1:])
    if res == root:
        print("True")
        return
    print("False")

# -------------------------------------------- SPARSE MERKLE TREE --------------------------------------------
class SparseMerkleTree:
    def __init__(self):
        self.depth_list = self.init_depth_list()
        self.root = self.depth_list[0]
        self.nodes = {}

    def init_depth_list(self):
        depth_list = [""] * 257
        last_depth = len(depth_list) - 1
        # Lowest level - hash of 2 leaves with value of 0
        depth_list[last_depth] = "0"
        i = last_depth - 1
        while i >= 0:
            depth_list[i] = encrypt_string(depth_list[i + 1] + depth_list[i + 1])
            i -= 1
        return depth_list

    def str_to_binary(self, digest):
        return str(bin(int(digest, 16)))[2:].zfill(256)

    def set_leaf(self, digest_leaf):
        digest_binary = self.str_to_binary(digest_leaf)
        # Set leaf
        self.nodes[digest_binary] = "1"
        # Now iterate until the root and update hash value of the nodes
        # Need to be 256
        digest_length = len(digest_binary)
        # Start from 255
        for i in range(digest_length - 1, 0, -1):
            # Get the key of the other node in the same depth
            if digest_binary[i] == "1":
                other_key = digest_binary[:i] + "0"
            else:
                other_key = digest_binary[:i] + "1"
            # Get the value of neighbor
            if other_key in self.nodes.keys():
                other_value = self.nodes[other_key]
            else:
                other_value = self.depth_list[i + 1]
            # Update value of father
            father_key = digest_binary[:i]
            # Check if this is the root
            if len(father_key) == 0:
                # if other is left child
                if other_key[i] == "0":
                    self.root = encrypt_string(other_value + self.nodes[digest_binary])
                # Other is right child
                else:
                    self.root = encrypt_string(self.nodes[digest_binary] + other_value)
                break
            # if other is left child
            if other_key[i] == "0":
                self.nodes[father_key] = encrypt_string(other_value + self.nodes[digest_binary])
            # Other is right child
            else:
                self.nodes[father_key] = encrypt_string(self.nodes[digest_binary] + other_value)
            digest_binary = father_key

        # Update root
        # Get the key of the other node in the same depth
        if digest_binary[0] == "1":
            other_key = digest_binary[:0] + "0"
        else:
            other_key = digest_binary[:0] + "1"
        # Get the value of neighbor
        if other_key in self.nodes.keys():
            other_value = self.nodes[other_key]
        else:
            other_value = self.depth_list[1]
        # if other is left child
        if other_key[0] == "0":
            self.root = encrypt_string(other_value + self.nodes[digest_binary])
        # Other is right child
        else:
            self.root = encrypt_string(self.nodes[digest_binary] + other_value)

    def create_spars_proof(self, digest):
        res = [self.root]
        # Create array of bits from the digest
        curr = self.str_to_binary(digest)
        # Find the first node that not trivial
        if not bool(self.nodes):
            res.append(self.root)
            print(*res)
            return
        not_trivial = None
        prev = curr
        while not_trivial is None:
            if curr in self.nodes:
                not_trivial = curr
                break
            prev = curr
            curr = curr[:-1]
            if len(curr) == 0:
                break
        if len(prev) < 256:
            res.append(self.depth_list[len(prev)])
        # Now we need to go up until the root and take the other child from every level
        while len(prev) > 0:
            other = None
            if prev[-1] == "1":
                other = prev[:-1] + "0"
            else:
                other = prev[:-1] + "1"
            if other in self.nodes:
                res.append(self.nodes[other])
            else:
                res.append(self.depth_list[len(prev)])
            prev = prev[:-1]
        print(*res)



def test_proof(cmd, tree):
    dep = 0
    dig = cmd[1]
    dig = str(bin(int(dig, 16)))[2:].zfill(256)
    # dig = int(dig, 16)
    val = cmd[2]
    value_calculate = ""
    root = cmd[3]
    first_val = cmd[4]
    tree_d = tree.depth_list
    for i in tree_d:
        if i == first_val:
            value_calculate = i
            break
        else:
            dep += 1
    length = len(cmd)
    for x in range(4, length):
        if dig[dep] == '1':
            value_calculate = encrypt_string(cmd[x] + value_calculate)
            hashlib.sha256(value_calculate.encode()).hexdigest()
        else:
            value_calculate = encrypt_string(value_calculate + cmd[x])
            hashlib.sha256(value_calculate.encode()).hexdigest()

    if root == value_calculate:
        if val == '1':
            print(True)
        else:
            print(False)
    else:
        if val == '1':
            print(False)
        else:
            print(True)



if __name__ == '__main__':
    merkle_tree = None
    sparseMerkleTree = SparseMerkleTree()
    command = input("")
    while command != 'exit':
        cmd_list = command.split()
        if len(cmd_list) == 0:
            command = input(">>> ")
            continue
        if cmd_list[0] == '1':
            # Create tree at the first time
            if merkle_tree is None:
                merkle_tree = MerkleTree()
            if len(cmd_list) == 2:
                # Add the leaf to the tree
                merkle_tree.insert_leaf(cmd_list[1])
        if cmd_list[0] == '2':
            # Print the root of the tree
            if merkle_tree is not None:
                print(merkle_tree.root.hash_value)
            else:
                print("")
        if cmd_list[0] == '3':
            # Proof of inclusion - get leaf num
            if len(cmd_list) == 2:
                proof_of_inclusion(merkle_tree, int(cmd_list[1]))
        if cmd_list[0] == '4':
            if len(cmd_list) >= 3:
                leaf_value = cmd_list[1]
                root = cmd_list[2]
                hash_list = cmd_list[3:]
                # Check Proof of inclusion
                check_proof_of_inclusion(leaf_value, root, hash_list)
            else:
                print("")
        if cmd_list[0] == '5':
            generate_rsa_keys()
        if cmd_list[0] == '6':
            if len(cmd_list) >= 2 and merkle_tree is not None:
                str_key = []
                str_key.append(cmd_list[1] + " " + cmd_list[2] + " " + cmd_list[3] + " " + cmd_list[4])
                sign_on_massage(str_key, merkle_tree.root.hash_value)
            else:
                print("")
        if cmd_list[0] == '7':
            if len(cmd_list) >= 4:
                str_key = []
                str_key.append(cmd_list[1] + " " + cmd_list[2] + " " + cmd_list[3])
                signature_verification(str_key)
        if cmd_list[0] == '8':
            if len(cmd_list) == 2:
                sparseMerkleTree.set_leaf(cmd_list[1])
            else:
                print("")
        if cmd_list[0] == '9':
            print(sparseMerkleTree.root)
        if cmd_list[0] == '10':
            if len(cmd_list) == 2:
                sparseMerkleTree.create_spars_proof(cmd_list[1])
        if cmd_list[0] == '11':
            if len(cmd_list) >= 4:
                test_proof(cmd_list, sparseMerkleTree)
        command = input("")
