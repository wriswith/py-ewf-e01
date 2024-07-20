import zlib

from binary_helper import convert_bin_to_int, convert_bin_to_text
from print_helper import print_hex_format, print_text, print_int, print_binary_format
from verify_hash import calculate_hash

# TODO: Check all the CRC checks
# TODO: verify how to write the table2 section


def parse_segment_header(input_e01):
    print(f"----------Segment header----------")
    print_hex_format(input_e01.read(8), "signature: ")
    print_hex_format(input_e01.read(1), "start of field: ")
    segment_number = convert_bin_to_int(input_e01.read(2))
    print(f"Segment number: {segment_number}")
    print_hex_format(input_e01.read(2), "footer: ")
    return segment_number


def convert_e01_to_dd(input_path, output_path):
    output_file = open(output_path, 'wb')
    with open(input_path, 'rb') as input_e01:
        parse_segment_header(input_e01)

        while True:
            section_type, next_section_offset, section_size = parse_section_descriptor(input_e01)
            if section_type == "header2":
                parse_header2_section(input_e01, section_size, next_section_offset)
            elif section_type == "header":
                parse_header_section(input_e01, section_size, next_section_offset)
            elif section_type == "volume":
                parse_volume_section(input_e01, section_size, next_section_offset)
            elif section_type == "sectors":
                parse_sectors_section(input_e01, section_size, next_section_offset, output_file)
            elif section_type == "table":
                parse_table_section(input_e01, section_size, next_section_offset)
            elif section_type == "table2":
                parse_table2_section(input_e01, section_size, next_section_offset)
            elif section_type == "data":
                parse_data_section(input_e01, section_size, next_section_offset)
            elif section_type == "digest":
                parse_digest_section(input_e01, section_size, next_section_offset)
            elif section_type == "hash":
                parse_hash_section(input_e01, section_size, next_section_offset)
            elif section_type == "done":
                print(f"End of image file.")
                break
            else:
                raise ValueError(f"Unknown section_type: {section_type}")
    output_file.close()


def parse_digest_section(input_e01, section_size, next_section_offset):
    print_hex_format(input_e01.read(16), "MD5 hash: ")
    print_hex_format(input_e01.read(20), "SHA1 hash: ")
    print_hex_format(input_e01.read(40), "padding: ")
    print_hex_format(input_e01.read(4), "checksum: ")


def parse_hash_section(input_e01, section_size, next_section_offset):
    print_hex_format(input_e01.read(16), "MD5 hash: ")
    print_hex_format(input_e01.read(16), "padding: ")
    print_hex_format(input_e01.read(4), "checksum: ")


def parse_table2_section(input_e01, section_size, next_section_offset):
    input_e01.read(section_size - 76)
    print(f"Skipping {section_size - 76} bytes of table2 data")


def parse_data_section(input_e01, section_size, next_section_offset):
    """
    Section containing similar data as the volume section, but is placed in subsequent segments instead of the first.
    In images consisting of one segment the section is added to the first segment.
    :param input_e01:
    :param section_size:
    :param next_section_offset:
    :return:
    """
    input_e01.read(section_size - 76)
    print(f"Skipping {section_size - 76} bytes of data_section data")


def parse_sectors_section(input_e01, sectors_section_size, next_section_offset, output_file):
    input_e01.seek(sectors_section_size - 76, 1)  # Skip to the table section
    start_of_table_section = input_e01.tell()
    section_type, next_section_offset, section_size = parse_section_descriptor(input_e01)
    if section_type != 'table':
        raise Exception(f'The first section after the sectors section should be a table section, not {section_type}')

    # Get the block offsets from the table section
    table_base_offset, block_offsets = parse_table_section(input_e01, section_size, next_section_offset)
    after_table_section = input_e01.tell()

    # Read the block from the sectors section
    for i in range(len(block_offsets)):
        compression = block_offsets[i][0]
        block_offset = block_offsets[i][1]
        print(f"Block offset {block_offsets[i]}")
        if i < len(block_offsets) - 1:
            block_size = block_offsets[i + 1][1] - block_offset
            print(f"Next block offset {block_offsets[i + 1]}")
        else:
            block_size = start_of_table_section - table_base_offset - block_offset

        print(f"Block size {block_size}")
        print(f"Current position = {input_e01.tell()}")
        input_e01.seek(table_base_offset + block_offset, 0)
        if compression:
            chunk_data = read_zlib_data(input_e01, block_size)
        else:
            chunk_data = input_e01.read(block_size - 4)
            checksum = convert_bin_to_int(input_e01.read(4))
            if zlib.adler32(chunk_data) != checksum:
                raise Exception(f"Checksum failure ({zlib.adler32(chunk_data)} != {checksum})")

        output_file.write(chunk_data)

    input_e01.seek(after_table_section, 0)
    section_type, next_section_offset, section_size = parse_section_descriptor(input_e01)
    if section_type == "table2":
        input_e01.seek(next_section_offset, 0)
    else:
        raise Exception(f"Table 2 section expected after table section.")


def parse_volume_section(input_e01, section_size, next_section_offset):
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


def parse_table_section(input_e01, section_size, next_section_offset):
    """
    Section containing the offsets at which the data blocks in the sectors section start.
    :param input_e01:
    :param section_size:
    :param next_section_offset:
    :return:
    """
    entries_number = convert_bin_to_int(input_e01.read(4))
    print(f"number of table entries: {entries_number}")
    print_hex_format(input_e01.read(4), "padding: ")
    table_base_offset = convert_bin_to_int(input_e01.read(8))
    print(f"table base offset: {table_base_offset}")
    print_hex_format(input_e01.read(4), "padding: ")
    print_hex_format(input_e01.read(4), "checksum: ")
    print(f"skipping {entries_number * 4} bytes of chunk offsets")
    entries_blob = input_e01.read(entries_number * 4)
    block_offsets = []
    for i in range(0, len(entries_blob), 4):
        # Read the entry value as int
        original_entry = int.from_bytes(entries_blob[i:i + 4], byteorder='little')
        # Read the actual offset without taking the MSB value into account which is a flag for compression
        msb_cleared_entry = original_entry & 0x7FFFFFFF
        # Store the compression flag in a separate boolean
        if original_entry == msb_cleared_entry:
            compression = False
        else:
            compression = True
        block_offsets.append((compression, msb_cleared_entry))
    print_hex_format(input_e01.read(4), "checksum: ")
    return table_base_offset, block_offsets


def parse_header_section(input_e01, section_size, next_section_offset):
    """
    Section containing metadata like examiner name and image acquisition date
    :param input_e01:
    :param section_size:
    :param next_section_offset:
    :return:
    """
    uncompressed_data = read_zlib_data(input_e01, section_size - 76)
    print_text(uncompressed_data, "header section data: |", footer="|")


def parse_section_descriptor(input_e01):
    print(f"----------Section descriptor----------")
    descriptor_blob = input_e01.read(72)
    try:
        type_blob = descriptor_blob[0:16]
        section_type = convert_bin_to_text(type_blob).rstrip('\x00')
        print(f"type: {section_type}")
        next_section_offset_blob = descriptor_blob[16:24]
        print_int(next_section_offset_blob, "offset to next section: ")
        section_size_blob = descriptor_blob[24:32]
        print_int(section_size_blob, "section size: ")
        print_hex_format(descriptor_blob[32:72], "Padding: ")
        checksum = convert_bin_to_int(input_e01.read(4))
        print(f"checksum: {checksum}")
        if zlib.adler32(descriptor_blob) != checksum:
            raise Exception(f"The checksum for the section descriptor is incorrect! ({zlib.adler32(descriptor_blob)} != {checksum}")
        return section_type, \
            convert_bin_to_int(next_section_offset_blob), \
            convert_bin_to_int(section_size_blob)
    except Exception as e:
        print_hex_format(descriptor_blob)
        raise e


def read_zlib_data(input_e01, size):
    compressed_data = input_e01.read(size)
    try:
        uncompressed_data = zlib.decompress(compressed_data)
    except zlib.error as e:
        print_hex_format(compressed_data)
        raise e
    return uncompressed_data


def parse_header2_section(input_e01, section_size, next_section_offset):
    """
    Payload are 2 bytes to set the UTF-16 byte order, followed by 17 lines separated by \x0a.
    :param input_e01:
    :return:
    """
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
    input_path_main = r"C:\temp\generated_test1.e01"
    # input_path_main = r"C:\Users\bruno\OneDrive - Office 365 GPI\Old\ewf-test\test1.E01"
    output_path_main = r"C:\temp\test1.dd"
    # input_path_main = r"C:\Users\447979443\OneDrive - Office 365 GPI\Old\ewf-test\test2.E01"
    # output_path_main = r"C:\temp\test2.dd"

    verification_dd_path = r"C:\Users\bruno\OneDrive - Office 365 GPI\Old\ewf-test\test1.dd"
    convert_e01_to_dd(input_path_main, output_path_main)
    print(calculate_hash(output_path_main))
    print(calculate_hash(verification_dd_path))
    # with open(output_path_main, 'rb') as t1:
    #     with open(verification_dd_path, 'rb') as t2:
    #         while True:
    #             blob1 = t1.read(50)
    #             blob2 = t2.read(50)
    #             if blob1 != blob2:
    #                 print_hex_format(blob1, 'unpacked dd    : ')
    #                 print_hex_format(blob2, 'verification dd: ')
    #                 print(t1.tell())
    #                 break

    # debug_e01(r"C:\Users\447979443\OneDrive - Office 365 GPI\Old\ewf-test\test2.E01")