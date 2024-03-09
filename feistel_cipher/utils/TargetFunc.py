
def target_func(sub_block, key):
    return ((sub_block << 9) ^ (~((key >> 11) ^ sub_block))) & 0xFF
