import zlib

from print_helper import print_binary_format, print_hex_format, print_bytes, print_text, print_int


def debug_e01(input_path):
    with open(input_path, 'rb') as input_e01:
        print(f"----------Segment header----------")
        print_hex_format(input_e01.read(8), "signature: ")
        print_hex_format(input_e01.read(1), "start of field: ")
        print_hex_format(input_e01.read(2), "Segment number: ")
        print_hex_format(input_e01.read(2), "footer: ")

        parse_header2_section(input_e01)
        parse_header2_section(input_e01)
        parse_header_section(input_e01)
        parse_volume_section(input_e01)
        parse_sectors_section(input_e01)
        parse_table_section(input_e01)
        parse_table2_section(input_e01)
        parse_data_section(input_e01)
        parse_digest_section(input_e01)
        parse_hash_section(input_e01)

        parse_section_descriptor(input_e01)


def parse_digest_section(input_e01):
    parse_section_descriptor(input_e01)
    print_hex_format(input_e01.read(16), "MD5 hash: ")
    print_hex_format(input_e01.read(20), "SHA1 hash: ")
    print_hex_format(input_e01.read(40), "padding: ")
    print_hex_format(input_e01.read(4), "checksum: ")

def parse_hash_section(input_e01):
    parse_section_descriptor(input_e01)
    print_hex_format(input_e01.read(16), "MD5 hash: ")
    print_hex_format(input_e01.read(16), "padding: ")
    print_hex_format(input_e01.read(4), "checksum: ")



def parse_table2_section(input_e01):
    section_size, next_section_offset = parse_section_descriptor(input_e01)
    input_e01.read(section_size - 76)
    print(f"Skipping {section_size - 76} bytes of table2 data")


def parse_data_section(input_e01):
    section_size, next_section_offset = parse_section_descriptor(input_e01)
    input_e01.read(section_size - 76)
    print(f"Skipping {section_size - 76} bytes of data_section data")


def parse_sectors_section(input_e01):
    section_size, next_section_offset = parse_section_descriptor(input_e01)
    input_e01.read(section_size - 76)
    print(f"Skipping {section_size - 76} bytes with the image data")


def parse_volume_section(input_e01):
    parse_section_descriptor(input_e01)
    print_hex_format(input_e01.read(1), "media type: ")
    print_hex_format(input_e01.read(3), "padding: ")
    print_int(input_e01.read(4), "chunk count: ")
    print_int(input_e01.read(4), "sectors per chunk: ")
    print_int(input_e01.read(4), "bytes per sector: ")
    print_int(input_e01.read(8), "sector count: ")
    print_int(input_e01.read(4), "cylinder count: ")
    print_int(input_e01.read(4), "heads count: ")
    print_int(input_e01.read(4), "sectors C:H:S count: ")
    print_hex_format(input_e01.read(1), "Media flags: ")
    print_hex_format(input_e01.read(3), "padding: ")
    print_int(input_e01.read(4), "PALM volume start sector: ")
    print_hex_format(input_e01.read(4), "padding: ")
    print_int(input_e01.read(4), "SMART logs start sector: ")
    print_int(input_e01.read(1), "Compression level: ")
    print_hex_format(input_e01.read(3), "padding: ")
    print_int(input_e01.read(4), "sector error granularity: ")
    print_hex_format(input_e01.read(4), "padding: ")
    print_hex_format(input_e01.read(16), "Segment file set identifier: ")
    print_hex_format(input_e01.read(963), "padding: ")
    print_hex_format(input_e01.read(5), "Signature (0x00): ")
    print_hex_format(input_e01.read(4), "checksum: ")


def parse_table_section(input_e01):
    parse_section_descriptor(input_e01)
    entries_number_blob = input_e01.read(4)
    entries_number = int.from_bytes(entries_number_blob, byteorder="little")
    print_int(entries_number_blob, "number of table entries: ")
    print_hex_format(input_e01.read(4), "padding: ")
    print_int(input_e01.read(8), "table base offset: ")
    print_hex_format(input_e01.read(4), "padding: ")
    print_hex_format(input_e01.read(4), "checksum: ")
    print(f"skipping {entries_number * 4} bytes of chunk offsets")
    input_e01.read(entries_number * 4)
    print_hex_format(input_e01.read(4), "checksum: ")




def parse_header_section(input_e01):
    section_size, next_section_offset = parse_section_descriptor(input_e01)
    uncompressed_data = read_zlib_data(input_e01, section_size - 76)
    print_text(uncompressed_data, "header section data: ")


def parse_section_descriptor(input_e01):
    print(f"----------Section descriptor----------")
    print_text(input_e01.read(16), "type: ")
    next_section_offset_blob = input_e01.read(8)
    print_int(next_section_offset_blob, "offset to next section: ")
    section_size_blob = input_e01.read(8)
    print_int(section_size_blob, "section size: ")
    print_hex_format(input_e01.read(40), "Padding: ")
    print_hex_format(input_e01.read(4), "checksum: ")
    return (int.from_bytes(section_size_blob, byteorder="little"),
            int.from_bytes(next_section_offset_blob, byteorder="little"))



def read_zlib_data(input_e01, size):
    compressed_data = input_e01.read(size)
    return zlib.decompress(compressed_data)


def parse_header2_section(input_e01):
    """
    Payload are 2 bytes to set the UTF-16 byte order, followed by 17 lines separated by \x0a.
    :param input_e01:
    :return:
    """
    section_size, next_section_offset = parse_section_descriptor(input_e01)
    print(f"----------data----------")
    uncompressed_data = read_zlib_data(input_e01, section_size - 76)
    print_hex_format(uncompressed_data)
    print_hex_format(uncompressed_data[0:2], "Byte order: ")
    start_next_line = 2
    for line_number in range(17):
        start_next_line = read_header_2_line(uncompressed_data, start_next_line)


def read_header_2_line(uncompressed_data, start_of_line):
    offset = start_of_line
    while uncompressed_data[offset:offset + 1] != b'\x0a':
        offset += 1
    print_text(uncompressed_data[start_of_line:offset], f"line ({offset}): ", "utf-16-le")
    offset += 2
    return offset



if __name__ == '__main__':
    debug_e01(r"C:\temp\test1.E01")