class Feistel:
    def __init__(self, sbox, pbox, key, rounds, blocksize, m):
        self.substitutions_box = sbox
        self.permutations_box  = pbox
        self.blocksize         = blocksize
        self.appended          = 0
        self.rounds            = rounds
        self.key               = key
        self.m                 = m
        # m = k * l with k, l in {x in Z | x mod 4 = 3}

    def binlist_2_int(self, l): return int(''.join(map(str, l)), 2)

    def int_2_binlist(self, k):
        return [int(bit) for bit in bin(k)[2:].zfill(len(self.key))]

    def split(self, l):
        assert len(l) % 2 == 0
        h = len(l) // 2
        return ([l[i] for i in range(h)], [l[h+i] for i in range(h)])

    def xor_arrays(self, a, b):
        assert len(a) == len(b)
        return [a[e] ^ b[e] for e in range(len(a))]
    
    def derive_key(self):
        """ 
        Blum Blum Shub pseudo-random number generator.
        => Generate a subkey for each round.
        """
        maximum = len(self.key)**2
        seed    = self.binlist_2_int(self.key)
        m       = self.m
        term    = seed**2
        for _ in range(10): term = term**2 % m

        keys = []
        for _ in range(self.rounds): keys.append(term**2 % m % maximum)
        return keys

    def roundfunc(self, right, roundkey):
        """
        The cipher round function, we first split the right 
        half in two to get a pair (row, col) used to get the
        corresponding value in the substitution box, and then 
        permute the result following the permutation box rules.
        """
        xored       = self.xor_arrays(right, roundkey)
        left, right = self.split(xored)
        col         = self.binlist_2_int(left)
        row         = self.binlist_2_int(right)
        # Substitute
        sub = self.substitutions_box[(col, row)]
        # Permute
        perm = [sub[self.permutations_box[i]] for i in range(len(sub))]
        return perm

    def encode_block(self, block):
        assert len(block) // 2 == len(self.key)
        assert len(block) == self.blocksize

        keys        = self.derive_key()
        keys        = [self.int_2_binlist(key) for key in keys]
        left, right = self.split(block)

        for rnd in range(self.rounds):
            _left, left = left, right
            right = self.xor_arrays(_left, self.roundfunc(right, keys[rnd]))

        return left + right

    def decode_block(self, block):
        assert len(block) // 2 == len(self.key)
        assert len(block) == self.blocksize

        keys        = self.derive_key()
        keys        = [self.int_2_binlist(key) for key in keys]
        left, right = self.split(block)

        for rnd in range(self.rounds - 1, -1, -1):
            _right, right = right, left
            left = self.xor_arrays(_right, self.roundfunc(left, keys[rnd]))

        return left + right
    
    def split_msg(self, msg):
        size, result, block = self.blocksize, result, block

        for i in range(len(msg)):
            if len(block) == size: result.append(block); block = []
            block.append(msg[i])

        if len(block) == 0: return result 

        # Padding
        while len(block) < self.blocksize: block.append(0); self.appended += 1

        result.append(block)
        return result

    def encode_msg(self, msg):
        blocks = self.split_msg(msg)
        f      = self.encode_block
        aux    = lambda L: [] if L == [] else f(L[0]) + aux(L[1:])

        return aux(blocks)

    def decode_msg(self, msg):
        blocks = self.split_msg(msg)
        f      = self.decode_block
        aux    = lambda L: [] if L == [] else f(L[0]) + aux(L[1:])

        result = aux(blocks)
        return result[:len(result)-self.appended]

gen_mod = lambda k, l: (4 * k - 1) * (4 * l - 1)

def main():
    SUBSTBOX = { (0, 0) : [1,1],
                 (1, 0) : [0,1],
                 (0, 1) : [1,0],
                 (1, 1) : [0,0], }
    PERMBOX    = [1, 0]
    K, L       = 9879, 4578
    ROUNDS     = 16
    BLOCK_SIZE = 4
    KEY        = [1, 0]
    MESSAGE    = [0, 1, 1, 1] + [1, 1, 0, 0] + [0, 0, 1, 0] + [0, 1, 1, 0]
    m          = gen_mod(K, L)

    cipher     = Feistel(SUBSTBOX, PERMBOX, KEY, ROUNDS, BLOCK_SIZE, m)
    ciphertext = cipher.encode_msg(MESSAGE)
    decoded    = cipher.decode_msg(ciphertext)

    print(f"Plain text: {cipher.binlist_2_int(MESSAGE):b}")
    print(f"Ciphertext: {cipher.binlist_2_int(ciphertext):b}")
    print(f"Decoded   : {cipher.binlist_2_int(decoded):b}")

    return None

if __name__ == '__main__': 
    main()

