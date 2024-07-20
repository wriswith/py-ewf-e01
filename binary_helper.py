

def convert_bin_to_int(input_bytes, byteorder="little"):
    return int.from_bytes(input_bytes, byteorder=byteorder, signed=False)


def convert_bin_to_text(input_bytes, encoding="ascii"):
    return input_bytes.decode(encoding)


def convert_int_to_bin(input_int, number_of_bytes, byteorder="little", signed=False):
    return int.to_bytes(input_int, length=number_of_bytes, byteorder=byteorder, signed=signed)


def pad_bytes(input_bytes, total_length):
    if len(input_bytes) > total_length:
        raise ValueError('')
    else:
        return input_bytes + b'\x00' * (total_length - len(input_bytes))
