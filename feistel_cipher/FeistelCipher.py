import sys

from feistel_cipher.utils.GenFunc import gen_func
from feistel_cipher.utils.SecretKeyGen import SecretKeyGen
from feistel_cipher.utils.TargetFunc import target_func

BLOCK_LEN = 16
BITS_IN_BYTE = 8
KEY_LEN = 64
ROUND_COUNT = 2


class FeistelCipher:
    def __init__(self, secret_key_gen, key_gen_func, target_gen_func, block_len=BLOCK_LEN, round_count=ROUND_COUNT):
        self.key = secret_key_gen()
        self.key_gen_func = key_gen_func
        self.target_gen_func = target_gen_func
        if not self.power_2_check(block_len):
            raise Exception("Block size must be a power of 2")
        self.bloc_len = block_len
        self.bytes_block_len = block_len // BITS_IN_BYTE
        if round_count < 2 or round_count > 12:
            raise Exception("Round count must be in the range from 2 to 12")
        self.round_count = round_count

    @staticmethod
    def power_2_check(n):
        return (n & (n - 1) == 0) and n != 0

    @staticmethod
    def to_binary_string(payload: str):
        byte_data = payload.encode('utf-8')
        binary_string = ''.join(format(byte, '08b') for byte in byte_data)
        return binary_string

    @staticmethod
    def from_binary_string(payload):
        payload_bytes = [int(payload[i:i + 8], 2) for i in range(0, len(payload), 8)]
        return bytes(payload_bytes).decode('utf-8')

    def split_to_blocks(self, string):
        blocks = [string[i:i + self.bytes_block_len] for i in range(0, len(string), self.bytes_block_len)]
        while len(blocks[-1]) != self.bytes_block_len:
            blocks[-1] += " "
        return blocks

    def encrypt(self, message: str):
        blocks = self.split_to_blocks(message)
        res = []
        for block in blocks:
            left_init = block[0]
            right_init = block[1]
            for iteration in range(self.round_count):
                curr_key = self.key_gen_func(self.key, iteration)
                print(curr_key)
                left = left_init
                right = right_init
                left_int = self.bintoint(self.stobin(left))
                right_int = self.bintoint(self.stobin(right))
                left_part_enc = self.target_gen_func(left_int, curr_key)
                xored = left_part_enc ^ right_int
                left_init = self.bintostr(self.itobin(xored))
                right_init = right
            res.append(left_init)
            res.append(right_init)
        return "".join(res)
        # blocks = self.split_to_blocks(message)
        # last_block_len = len(blocks[len(blocks) - 1])
        #
        # if last_block_len < self.bytes_block_len:
        #     for i in range(last_block_len, self.bytes_block_len):
        #         blocks[len(blocks) - 1] += " "
        # print(blocks)
        # for block in blocks:
        #     left = [""] * (self.round_count + 1)
        #     right = [""] * (self.round_count + 1)
        #     left[0] = block[0:self.bytes_block_len // 2]
        #     right[0] = block[self.bytes_block_len // 2:self.bytes_block_len]
        #
        #     for iteration in range(0, self.round_count):
        #         curr_key = self.key_gen_func(self.key, iteration)
        #         int_left = self.bintoint(self.stobin(left[iteration]))
        #         int_right = self.bintoint(self.stobin(right[iteration]))
        #         generated_left = self.target_gen_func(int_left, curr_key)
        #         xored = generated_left ^ int_right
        #
        #         new_left = xored
        #         print(sys.getsizeof(new_left))
        #         new_right = int_left

                # generated_left = self.target_gen_func(new_left, curr_key)
                #
                # new = generated_left ^ new_right
                #
                # s1 = self.itobin(new)
                # print(len(s1))
                #
                # print(self.bintostr(s1))
                #
                # print(sys.getsizeof(xored))
                # print(self.bintostr(self.itobin(xored)))
                # self.call_target(left[iteration], curr_key)
                # right[iteration + 1] = xor(left[iteration], scramble(right[iteration], iteration + 1, curr_key))

    def call_target(self, left, key):
        x = self.stobin(str(left))
        x = self.bintoint(x)
        res = self.target_gen_func(x, key)
        return self.bintostr(self.itobin(res))

    # xor two strings
    @staticmethod
    def xor(s1, s2):
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

    # string to binary
    @staticmethod
    def stobin(s):
        return ''.join('{:08b}'.format(ord(c)) for c in s)

    # binary to int
    @staticmethod
    def bintoint(s):
        return int(s, 2)

    # int to binary
    @staticmethod
    def itobin(i):
        return bin(i)[2:]

    # binary to string
    @staticmethod
    def bintostr(b):
        n = int(b, 2)
        return ''.join(chr(int(b[i: i + 8], 2)) for i in range(0, len(b), 8))

        # binary_string = self.to_binary_string(message)
        # binary_blocks = self.split_to_blocks(binary_string)
        # print(binary_blocks)
        # res_blocks = []
        # for block in binary_blocks:
        #     r_right = block[len(block) // 2:].zfill(self.bloc_len // 2)
        #     r_left = block[:len(block) // 2].zfill(self.bloc_len // 2)
        #     for iteration in range(self.round_count):
        #         curr_key = self.key_gen_func(self.key, iteration)
        #         right = r_right
        #         left = r_left
        #
        #         left_part_enc = self.target_gen_func(int(left, 2), curr_key)
        #         xored = (left_part_enc ^ int(right, 2))
        #         print(bin(xored & ((1 << 64) - 1))[2:].zfill(64))
        #         print(len(bin(xored)))
        #         new_left = bin(xored)[2:].zfill(self.bloc_len // 2)
        #         new_right = left
        #
        #         r_right = new_right
        #         r_left = new_left
        #     res_blocks.append(r_left)
        #     res_blocks.append(r_right)
        # return "".join(res_blocks)

    def decrypt(self, bits):
        binary_blocks = self.split_to_blocks(bits)

        res = []
        for block in binary_blocks:
            left_init = block[0]
            right_init = block[1]
            for iteration in range(self.round_count - 1, -1, -1):
                curr_key = self.key_gen_func(self.key, iteration)
                print(curr_key)
                left = left_init
                right = right_init
                left_int = self.bintoint(self.stobin(left))
                right_int = self.bintoint(self.stobin(right))
                left_part_enc = self.target_gen_func(left_int, curr_key)
                xored = left_part_enc ^ right_int
                left_init = self.bintostr(self.itobin(xored))
                right_init = right
            res.append(left_init)
            res.append(right_init)
        return "".join(res)
        #     r_right = block[len(block) // 2:].zfill(self.bloc_len // 2)
        #     r_left = block[:len(block) // 2].zfill(self.bloc_len // 2)
        #     for iteration in range(self.round_count - 1, -1, -1):
        #         curr_key = self.key_gen_func(self.key, iteration)
        #         right = r_right
        #         left = r_left
        #         left_part_dec = self.target_gen_func(int(left, 2), curr_key)
        #         xored = (left_part_dec ^ int(right, 2))
        #         new_left = bin(xored)[2:].zfill(self.bloc_len // 2)
        #         new_right = left
        #
        #         r_right = new_right
        #         r_left = new_left
        #     res_blocks.append(r_left)
        #     res_blocks.append(r_right)
        # for block in res_blocks:
        #     print(self.from_binary_string(block))


if __name__ == '__main__':
    key_generator = SecretKeyGen(KEY_LEN)
    fc = FeistelCipher(key_generator, gen_func, target_func)
    enc = fc.encrypt("hello")
    print(enc)
    print(fc.decrypt(enc))
