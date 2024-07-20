import binascii


def print_bytes(input_bytes, label=""):
    print_binary_format(input_bytes, label)
    print_hex_format(input_bytes, label)


def print_binary_format(input_bytes, label=""):
    print(label + ' '.join(format(byte, '08b') for byte in input_bytes))


def print_hex_format(input_bytes, label=""):
    print(label + ' '.join(f'\\x{byte:02x}' for byte in input_bytes))


def print_text(input_bytes, label="", footer="", encoding='ascii'):
    print(label + input_bytes.decode(encoding) + footer)


def print_int(input_bytes, label=""):
    print(label + str(int.from_bytes(input_bytes, byteorder="little")))
