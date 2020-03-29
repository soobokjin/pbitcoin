import math

from io import BytesIO
from unittest import TestCase

from pbitcoin.helper.helper import (
    bytes_to_bit_field,
    little_endian_to_int,
    merkle_parent,
    read_varint,
)


class MerkleTree:
    def __init__(self, total):
        self.total = total
        self.max_depth = math.ceil(math.log(self.total, 2))
        self.nodes = []
        for depth in range(self.max_depth + 1):
            num_items = math.ceil(self.total / 2 ** (self.max_depth - depth))
            level_hashes = [None] * num_items
            self.nodes.append(level_hashes)
        self.current_depth = 0  # <1>
        self.current_index = 0

    def __repr__(self):  # <2>
        result = []
        for depth, level in enumerate(self.nodes):
            items = []
            for index, h in enumerate(level):
                if h is None:
                    short = 'None'
                else:
                    short = '{}...'.format(h.hex()[:8])
                if depth == self.current_depth and index == self.current_index:
                    items.append('*{}*'.format(short[:-2]))
                else:
                    items.append('{}'.format(short))
            result.append(', '.join(items))
        return '\n'.join(result)

    def up(self):
        self.current_depth -= 1
        self.current_index //= 2

    def left(self):
        self.current_depth += 1
        self.current_index *= 2

    def right(self):
        self.current_depth += 1
        self.current_index = self.current_index * 2 + 1

    def root(self):
        return self.nodes[0][0]

    def set_current_node(self, value):  # <1>
        self.nodes[self.current_depth][self.current_index] = value

    def get_current_node(self):
        return self.nodes[self.current_depth][self.current_index]

    def get_left_node(self):
        return self.nodes[self.current_depth + 1][self.current_index * 2]

    def get_right_node(self):
        return self.nodes[self.current_depth + 1][self.current_index * 2 + 1]

    def is_leaf(self):  # <2>
        return self.current_depth == self.max_depth

    def right_exists(self):  # <3>
        return len(self.nodes[self.current_depth + 1]) > \
               self.current_index * 2 + 1

    def populate_tree(self, flag_bits, hashes):
        while self.root() is None:  # <1>
            if self.is_leaf():  # <2>
                flag_bits.pop(0)  # <3>
                self.set_current_node(hashes.pop(0))  # <4>
                self.up()
            else:
                left_hash = self.get_left_node()
                if left_hash is None:  # <5>
                    if flag_bits.pop(0) == 0:  # <6>
                        self.set_current_node(hashes.pop(0))
                        self.up()
                    else:
                        self.left()  # <7>
                elif self.right_exists():  # <8>
                    right_hash = self.get_right_node()
                    if right_hash is None:  # <9>
                        self.right()
                    else:  # <10>
                        self.set_current_node(merkle_parent(left_hash,
                                                            right_hash))
                        self.up()
                else:  # <11>
                    self.set_current_node(merkle_parent(left_hash, left_hash))
                    self.up()
        if len(hashes) != 0:  # <12>
            raise RuntimeError('hashes not all consumed {}'.format(len(hashes)))
        for flag_bit in flag_bits:  # <13>
            if flag_bit != 0:
                raise RuntimeError('flag bits not all consumed')
