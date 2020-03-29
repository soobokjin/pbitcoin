from pbitcoin.helper.helper import little_endian_to_int, int_to_little_endian, hash256, bits_to_target, \
    merkle_parent_level, merkle_root


class Block:

    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce, tx_hashes=None):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes

    # end::source1[]

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses a block. Returns a Block object'''

        # version - 4 bytes, little endian, interpret as int
        version: int = little_endian_to_int(s.read(4))
        # prev_block - 32 bytes, little endian (use [::-1] to reverse)
        prev_block: bytes = s.read(32)[::-1]
        # merkle_root - 32 bytes, little endian (use [::-1] to reverse)
        merkle_root: bytes = s.read(32)[::-1]
        # timestamp - 4 bytes, little endian, interpret as int
        timestamp: int = little_endian_to_int(s.read(4))
        # bits - 4 bytes
        bits: bytes = s.read(4)
        # nonce - 4 bytes
        nonce: bytes = s.read(4)

        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += self.prev_block[::-1]
        result += self.merkle_root[::-1]
        result += int_to_little_endian(self.timestamp, 4)
        result += self.bits
        result += self.nonce
        return result

    def hash(self):
        s = self.serialize()
        sha = hash256(s)
        return sha[::-1]

    def validate_merkle_root(self):
        '''Gets the merkle root of the tx_hashes and checks that it's
        the same as the merkle root of this block.
        '''
        # reverse each item in self.tx_hashes
        tx_hashes = [tx_hash[::-1] for tx_hash in self.tx_hashes]

        # compute the Merkle Root and reverse
        m_root = merkle_root(tx_hashes)[::-1]

        return self.merkle_root == m_root

    def bip9(self):
        '''Returns whether this block is signaling readiness for BIP9'''
        return self.version >> 29 == 0b001

    def bip91(self):
        '''Returns whether this block is signaling readiness for BIP91'''
        # BIP91 is signalled if the 5th bit from the right is 1
        # shift 4 bits to the right and see if the last bit is 1
        return self.version >> 4 & 1 == 1

    def bip141(self):
        '''Returns whether this block is signaling readiness for BIP141'''
        # BIP91 is signalled if the 2nd bit from the right is 1
        # shift 1 bit to the right and see if the last bit is 1
        return self.version >> 1 & 1 == 1

    def target(self):
        '''Returns the proof-of-work target based on the bits'''
        return bits_to_target(self.bits)

    def difficulty(self):
        '''Returns the block difficulty based on the bits'''
        # note difficulty is (target of lowest difficulty) / (self's target)
        # lowest difficulty has bits that equal 0xffff001d
        lowest = 0xffff * 256 ** (0x1d - 3)
        return lowest / self.target()

    def check_pow(self):
        '''Returns whether this block satisfies proof of work'''
        # get the hash256 of the serialization of this block
        h256 = hash256(self.serialize())
        # interpret this hash as a little-endian number
        proof = little_endian_to_int(h256)
        # return whether this integer is less than the target
        return proof < self.target()
