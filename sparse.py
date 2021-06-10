# Get string and return sha256 of the string
import hashlib


def encrypt_string(str_input):
    return hashlib.sha256(str_input.encode()).hexdigest()


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


if __name__ == '__main__':
    sparseMerkleTree = SparseMerkleTree()
    print('Welcome!')
    print('Type \'quit\' to close the app')
    command = input(">>> ")
    while command != 'exit':
        cmd_list = command.split()
        if cmd_list[0] == '8':
            if len(cmd_list) == 2:
                sparseMerkleTree.set_leaf(cmd_list[1])
            else:
                print("")
        if cmd_list[0] == '9':
            print(sparseMerkleTree.root)
        # if cmd_list[0] == '10':
        #
        # if cmd_list[0] == '11':
        command = input(">>> ")
