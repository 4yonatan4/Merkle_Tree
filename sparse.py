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
        depth_list = [""] * 256
        last_depth = len(depth_list) - 1
        # Lowest level - hash of 2 leaves with value of 0
        depth_list[last_depth] = encrypt_string("0" + "0")
        i = last_depth - 1
        while i >= 0:
            depth_list[i] = encrypt_string(depth_list[i + 1] + depth_list[i + 1])
            i -= 1
        return


    def set_leaf(self, digest_leaf):



if __name__ == '__main__':
    sparseMerkleTree = SparseMerkleTree()
    print('Welcome!')
    print('Type \'quit\' to close the app')
    command = input(">>> ")
    while command != 'exit':
        cmd_list = command.split()
        if cmd_list[0] == '8':

        if cmd_list[0] == '9':
            print(sparseMerkleTree.root)
        if cmd_list[0] == '10':

        if cmd_list[0] == '11':


        command = input(">>> ")