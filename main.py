class Feistel:
    def __init__(self, roundf, rounds, bsize, key, derivf):
        assert bsize    > 0
        assert len(key) == bsize // 2
        assert rounds   > 0

        self.round_func      = roundf
        self.derive_key      = derivf
        self.rounds          = rounds
        self.block_size      = bsize
        self.key             = key

    def pad_msg(self, msg: bytes) -> bytes:
        """
        Pad the plaintext using the following technique: append the required 
        number of 0's to the end, and write this number in the last byte. 
        """
        bytes_to_append = self.block_size - ((len(msg) + 1) % self.block_size)
        last_block = bytes([bytes_to_append + 1])

        for _ in range(bytes_to_append): msg += bytes([0x0])

        return msg + last_block

    def rm_padding(self, msg: bytes) -> bytes:
        """
        Remove the padding from the plaintext.
        """
        bytes_appended = msg[len(msg)-1]

        return msg[:len(msg) - bytes_appended]

    def split_msg(self, msg) -> list[bytes]:
        """
        Divide the message into blocks of size block_size.
        """
        assert len(msg) % self.block_size == 0

        blocks, index = [], 0

        for _ in range(len(msg)):
            block = []
            for _ in range(self.block_size):
                if index >= len(msg): return blocks
                block.append(msg[index])
                index += 1
            blocks.append(block)

        return blocks

    def split_block(self, block : bytes) -> (bytes, bytes):
        """
        Split the block in half.
        """
        assert len(block) == self.block_size

        half = self.block_size // 2
        return block[:half], block[half:] # (L, R)
    
    def XOR(self, bytesA, bytesB):
        """
        From two list of bytes A and B where |A| = |B|, 
        returns [A[i] ^ B[i] | 0 <= i < len(A)].
        """
        assert len(bytesA) == len(bytesB)

        return [a ^ b for (a, b) in zip(bytesA, bytesB)]

    def encode_block(self, block : bytes) -> bytes:
        """
        Encode a block.
        """
        assert len(block) == self.block_size

        left, right = self.split_block(block)
        keys = self.derive_key(self.key, self.rounds)

        for r in range(self.rounds):
            # L_i+1 = R_i
            left, prevleft, prevright = right, left, right
            # R_i+1 = L_i ^ f(R_i ^ K_i)
            right = self.XOR(prevleft, (self.round_func(self.XOR(prevright, keys[r]))))

        return left + right

    def decode_block(self, block : bytes) -> bytes:
        """
        Decode a block.
        """
        assert len(block) == self.block_size

        left, right = self.split_block(block)
        keys = self.derive_key(self.key, self.rounds)

        for r in range(self.rounds):
            # R_i = L_i+1
            right, prevright, prevleft = left, right, left
            # L_i = R_i+1 ^ f(L_i+1 ^ K_i)
            left = self.XOR(prevright, (self.round_func(self.XOR(prevleft, keys[r]))))

        return left + right

def main():
    make_roundf = lambda pbox, sbox: (lambda block: bytes(block))
    derivf = lambda key, rounds: [key for _ in range(rounds)]

    msg = "hey₤"
    print(f"Message: {msg}")

    msg = bytes(msg, "utf-8")

    blocksize = 4
    key = bytes([i for i in range(blocksize//2)])

    ciph = Feistel(make_roundf([], []), 16, blocksize, key, derivf)

    padded = ciph.pad_msg(msg)
    print(f"Padded: {padded}")

    blocks = ciph.split_msg(padded)
    print(f"Splitted: {blocks}")

    encoded = [ciph.encode_block(block) for block in blocks]
    print(f"Encoded: {encoded}")

    decoded = []
    for block in encoded: decoded += ciph.decode_block(block)
    print(f"Decoded: {decoded}")

    depadded = ciph.rm_padding(decoded)
    print(f"De-padded: {depadded}")

    decoded_msg = bytes(depadded)
    print(f"Decoded message: {str(decoded_msg, 'utf-8')}")

if __name__ == '__main__': main()

