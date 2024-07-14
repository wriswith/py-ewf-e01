

def convert_bin_to_int(input_bytes, byteorder="little"):
    return int.from_bytes(input_bytes, byteorder=byteorder)


def convert_bin_to_text(input_bytes, encoding="ascii"):
    return input_bytes.decode(encoding)
