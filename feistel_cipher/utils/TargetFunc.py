
def target_func(sub_block, key, max_bits):
    return ((sub_block << 9) ^ (~((key >> 11) ^ sub_block))) & ((1 << max_bits) - 1)
