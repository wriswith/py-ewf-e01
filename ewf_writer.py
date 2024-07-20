import datetime
import hashlib
import math
import os
import time
import uuid
import zlib

from binary_helper import convert_int_to_bin

from binary_helper import pad_bytes


def create_segment_file(output_path, sequence_number):
    # TODO: calculate correct extension if sequence_number is not 1
    segment_file = open(output_path, "wb+")
    segment_file.write(b'\x45\x56\x46\x09\x0d\x0a\xff\x00\x01')  # Static signature + static start of field
    segment_file.write(convert_int_to_bin(sequence_number, number_of_bytes=2))
    segment_file.write(b'\x00\x00')  # Static end of fields
    return segment_file


def write_dummy_header2_section(segment_file):
    uncompressed_data = b'\xff\xfe'
    acquisition_time = int(time.time())
    # lines taken from a test image with most values cleared out
    lines = ['3', 'main', 'a	c	n	e	t	md	sn	av	ov	m	u	p	dc',
             f'description									{acquisition_time}	{acquisition_time}	0	',
             '', 'srce', '0	1', 'p	n	id	ev	tb	lo	po	ah	gu	aq', '0	0',
             '					-1	-1			', '', 'sub', '0	1', 'p	n	id	nu	co	gu',
             '0	0', '				1	', '']
    uncompressed_data += ('\n'.join(lines) + '\n').encode('utf-16-le')
    compressed_data = zlib.compress(uncompressed_data, level=5)
    write_section_descriptor(segment_file, 'header2', len(compressed_data))
    segment_file.write(compressed_data)


def write_dummy_header_section(segment_file):
    acquisition_time = int(time.time())
    dt_object = datetime.datetime.fromtimestamp(acquisition_time)
    formatted_time = dt_object.strftime('%Y %B %d %H %M %S')

    # lines taken from a test image with most values cleared out
    lines = ['1', 'main', 'c	n	a	e	t	av	ov	m	u	p',
             f'		description				Python	{formatted_time}	{formatted_time}	0', '']
    uncompressed_data = ('\n'.join(lines) + '\n').encode('ASCII')
    compressed_data = zlib.compress(uncompressed_data, level=5)
    write_section_descriptor(segment_file, 'header', len(compressed_data))
    segment_file.write(compressed_data)


def write_section_descriptor(segment_file, section_type, data_length):
    offset_start_of_section = segment_file.tell()
    section_descriptor_blob = pad_bytes(section_type.encode('ascii'), 16)  # Add section type
    if section_type == "done":
        section_descriptor_blob += convert_int_to_bin(offset_start_of_section, 8)  # Set offset next section to start of this section as it is the last section
    else:
        section_descriptor_blob += convert_int_to_bin(offset_start_of_section + 76 + data_length, 8)  # Add offset next section
    section_descriptor_blob += convert_int_to_bin(76 + data_length, 8)  # add section size
    section_descriptor_blob += b'\x00' * 40
    section_descriptor_blob += convert_int_to_bin(zlib.adler32(section_descriptor_blob), 4)   # Add checksum
    segment_file.write(section_descriptor_blob)


def get_volume_metadata(input_path, image_guid):
    # TODO: choose whether to implement the physical device flag or to always set

    volume_metadata = {'sectors_per_chunk': 64, 'bytes_per_sector': 512, 'media_flags': b'\x03', 'compression_level': 1,
                       'sector_error_granularity': 64, 'image_guid': image_guid}
    source_size = os.stat(input_path).st_size
    volume_metadata['sector_count'] = int(source_size / volume_metadata['bytes_per_sector'])
    volume_metadata['chunk_count'] = math.ceil(volume_metadata['bytes_per_sector'] / volume_metadata['sectors_per_chunk'])
    return volume_metadata


def write_volume_section(segment_file, volume_metadata):
    volume_section = format_volume_metadata(volume_metadata)
    write_section_descriptor(segment_file, "volume", len(volume_section))
    segment_file.write(volume_section)


def format_volume_metadata(volume_metadata):
    volume_data = b'\x01'  # media type
    volume_data += b'\x00' * 3  # padding
    volume_data += convert_int_to_bin(volume_metadata['chunk_count'], 4)
    volume_data += convert_int_to_bin(volume_metadata['sectors_per_chunk'], 4)
    volume_data += convert_int_to_bin(volume_metadata['bytes_per_sector'], 4)
    volume_data += convert_int_to_bin(volume_metadata['sector_count'], 8)
    volume_data += convert_int_to_bin(0, 4)  # unused C:H:S value
    volume_data += convert_int_to_bin(0, 4)  # unused C:H:S value
    volume_data += convert_int_to_bin(0, 4)  # unused C:H:S value
    volume_data += volume_metadata['media_flags']
    volume_data += b'\x00' * 3  # padding
    volume_data += b'\x00' * 4  # PALM volume start sector
    volume_data += b'\x00' * 4  # padding
    volume_data += b'\x00' * 4  # SMART logs start sector
    volume_data += convert_int_to_bin(volume_metadata['compression_level'], 1)
    volume_data += b'\x00' * 3  # padding
    volume_data += convert_int_to_bin(volume_metadata['sector_error_granularity'], 4)
    volume_data += b'\x00' * 4  # SMART logs start sector
    volume_data += volume_metadata['image_guid']
    volume_data += b'\x00' * 963  # padding
    volume_data += b'\x00' * 5  # Signature (Reserved)
    volume_data += convert_int_to_bin(zlib.adler32(volume_data), 4)
    return volume_data


def write_sectors_section(segment_file, input_path, volume_metadata):
    chunk_size = volume_metadata['sectors_per_chunk'] * volume_metadata['bytes_per_sector']
    md5_calculator = hashlib.md5()
    sha1_calculator = hashlib.sha1()
    image_complete = False

    with open(input_path, 'rb') as input_file:
        while not image_complete:
            start_of_section = segment_file.tell()
            table_base_offset = start_of_section
            # Write an empty descriptor as we need to write the data first to get the section length
            segment_file.write(b'\x00' * 76)
            start_of_sectors_data = segment_file.tell()

            chunk_offsets = []
            while True:
                offset = segment_file.tell() - start_of_section
                if offset > 0x7FFFFFFF:
                    break  # Sectors section is full. Write table section and start new sectors section
                chunk = input_file.read(chunk_size)
                if not chunk:
                    image_complete = True
                    break

                compressed_chunk = zlib.compress(chunk)

                if len(chunk) < len(compressed_chunk):
                    segment_file.write(chunk)
                    segment_file.write(convert_int_to_bin(zlib.adler32(chunk), 4))
                else:
                    offset = offset | 0x80000000   # Set the MSB to 1 to set the compression flag
                    segment_file.write(compressed_chunk)
                chunk_offsets.append(convert_int_to_bin(offset, 4))
                md5_calculator.update(chunk)
                sha1_calculator.update(chunk)

            end_of_section = segment_file.tell()
            segment_file.seek(start_of_section)
            write_section_descriptor(segment_file, "sectors", end_of_section - start_of_sectors_data)
            segment_file.seek(end_of_section)

            # Write table and table2 section
            write_table_section(segment_file, table_base_offset, chunk_offsets)

    return md5_calculator.digest(), sha1_calculator.digest()


def write_table_section(segment_file, table_base_offset, chunk_offsets):
    # generate table header
    table_data = convert_int_to_bin(len(chunk_offsets), 4)
    table_data += b"\x00" * 4
    table_data += convert_int_to_bin(table_base_offset, 8)
    table_data += b"\x00" * 4
    table_data += convert_int_to_bin(zlib.adler32(table_data), 4)

    # generate table entries
    chunk_offsets_blob = b''.join(chunk_offsets)
    table_data += chunk_offsets_blob

    # generate table footer
    table_data += convert_int_to_bin(zlib.adler32(chunk_offsets_blob), 4)

    # Write to file
    write_section_descriptor(segment_file, "table", len(table_data))
    segment_file.write(table_data)

    # Generate the mirror for recovery purposes
    write_section_descriptor(segment_file, "table2", len(table_data))
    # Reverse the bits in each byte
    reversed_bits_data = bytes(int('{:08b}'.format(byte)[::-1], 2) for byte in table_data)
    # Reverse the order of the bytes
    mirrored_data = reversed_bits_data[::-1]
    segment_file.write(mirrored_data)


def write_data_section(segment_file, volume_metadata):
    volume_section = format_volume_metadata(volume_metadata)
    write_section_descriptor(segment_file, "data", len(volume_section))
    segment_file.write(volume_section)


def write_digest_section(segment_file, md5_hash, sha1_hash):
    write_section_descriptor(segment_file, 'digest', 80)
    digest_data = md5_hash
    digest_data += sha1_hash
    digest_data += b'\x00' * 40
    segment_file.write(digest_data)
    segment_file.write(convert_int_to_bin(zlib.adler32(digest_data), 4))
    
    pass


def write_hash_section(segment_file, md5_hash):
    write_section_descriptor(segment_file, 'hash', 36)
    hash_data = md5_hash
    hash_data += b'\x00' * 16
    segment_file.write(hash_data)
    segment_file.write(convert_int_to_bin(zlib.adler32(hash_data), 4))


def write_done_section(segment_file):
    write_section_descriptor(segment_file, 'done', 0)


def convert_dd_to_e01(input_path, output_path):
    image_guid = uuid.uuid4().hex[0:16].encode("ASCII")

    # create new segment file
    segment_file = create_segment_file(output_path, 1)

    # generate empty header2 and header
    write_dummy_header2_section(segment_file)
    write_dummy_header2_section(segment_file)   # Was writen twice in the X-Ways image. Not necessary according to spec.
    write_dummy_header_section(segment_file)

    # calculate values for volume & data section
    volume_metadata = get_volume_metadata(input_path, image_guid)

    # write volume section
    write_volume_section(segment_file, volume_metadata)

    # Write data into sectors section
    md5_hash, sha1_hash = write_sectors_section(segment_file, input_path, volume_metadata)

    # Write offsets into table & table 2 section

    # Write data section
    # Todo: Only write this at end of file if this is the image has only one segment
    write_data_section(segment_file, volume_metadata)

    # Write digest, hash and done section
    write_digest_section(segment_file, md5_hash, sha1_hash)
    write_hash_section(segment_file, md5_hash)
    write_done_section(segment_file)

    pass


if __name__ == '__main__':
    input_path_main = r"C:\Users\bruno\OneDrive - Office 365 GPI\Old\ewf-test\test1.dd"
    output_path_main = r"C:\temp\generated_test1.e01"
    convert_dd_to_e01(input_path_main, output_path_main)
