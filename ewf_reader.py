import logging
import zlib
from datetime import datetime
from multiprocessing import Queue, Process
from threading import Thread

from binary_helper import convert_bin_to_int, convert_bin_to_text
from print_helper import print_hex_format, print_text, print_int, print_binary_format
from verify_hash import calculate_hash

# TODO: verify how to write / verify the table2 section. This section is made for data recovery purposes.


def parse_segment_header(input_e01, segment_id):
    """
    Parse the segment header. It only contains the segment_id.
    :param input_e01:
    :param segment_id:
    :return:
    """
    logging.debug(f"----------Segment header----------")
    print_hex_format(input_e01.read(8), "signature: ")
    print_hex_format(input_e01.read(1), "start of field: ")
    segment_number = convert_bin_to_int(input_e01.read(2))
    if segment_id != segment_number:
        raise Exception(f"The segment number does not match the expected value: expected={segment_id}, "
                        f"read={segment_number}")
    logging.debug(f"Segment number: {segment_number}")
    print_hex_format(input_e01.read(2), "footer: ")
    return segment_number


def convert_e01_to_dd(input_path, output_path, threads=5, skip_data=False, start_from_segment=1):
    """
    Read the input file and write the data to a raw file.
    :param input_path: Path to the first segment of the image or to the file without extension.
    :param output_path: File path where the raw file will be written to.
    :param threads:
    :param skip_data: Debug option to check the consistency of the image. The actual data chunks are skipped.
    :param start_from_segment: Option to start parsing in the middle of the image. Only useful for corrupt images.
    :return:
    """
    with open(output_path, 'wb') as output_file:
        image_done = False
        segment_number = start_from_segment
        while not image_done:
            image_done, md5_hash = process_segment(input_path, output_file, segment_number, threads, skip_data)
            segment_number += 1
        logging.info(f"Finished reading data.")


def generate_segment_path(input_path, segment_id):
    """
    Generates the path with the correct extension for the requested segment_id.
    :param input_path: Path to first segment or path to segment with extension removed.
    :param segment_id:
    :return:
    """
    # Remove existing extension if present
    if input_path.endswith('.e01') or input_path.endswith('.E01'):
        input_path = input_path[:-4]

    if segment_id < 100:
        return f"{input_path}.e{"%02d" % (segment_id,)}"
    else:
        raise NotImplementedError(f"Counting rules past e99 are not implemented.")


def process_segment(input_path, output_file, segment_id, threads=5, skip_data=False):
    """
    Process a segment file. The data in the sectors sections will be processed and written to the output_file. If the
    last section is 'next', (False, None) will be returned to signal the file is not done. If the last section is
    'done', (True, md5_hash) will be returned. md5_hash will contain the hash from the hash section if this section is
    present.
    :param input_path: Path to the first segment of the image or file without extension.
    :param output_file: File object to write output to.
    :param segment_id: ID of the segment that will be read. This ID determines the extension of the file.
    :param threads: Number of chunk_processes to spawn.
    :param skip_data: Debug option to check the consistency of the segment file. The actual data chunks are skipped.
    :return:
    """
    segment_file_name = generate_segment_path(input_path, segment_id)
    md5_hash = None

    chunk_processors = []
    chunk_process_queues = []
    chunk_result_queues = []
    for i in range(threads):
        chunk_process_queues.append(Queue())
        chunk_result_queues.append(Queue())
        chunk_processors.append(Process(target=chunk_worker, args=(chunk_process_queues[i], chunk_result_queues[i])))
        chunk_processors[i].start()

    writer_thread = Thread(target=file_writer, args=(output_file, chunk_result_queues))
    writer_thread.start()

    with open(segment_file_name, 'rb') as input_segment:
        parse_segment_header(input_segment, segment_id)
        chunk_sequence_number = 0

        while True:
            # Read and parse the header of the next section
            try:
                section_type, next_section_offset, section_size = parse_section_descriptor(input_segment)
            except Exception as e:
                close_chunk_processors(chunk_process_queues, chunk_processors, writer_thread)
                raise e

            # Parse the section based on the section type extracted from the header
            if section_type == "header2":
                parse_header2_section(input_segment, section_size, next_section_offset)
            elif section_type == "header":
                parse_header_section(input_segment, section_size, next_section_offset)
            elif section_type == "volume":
                parse_volume_section(input_segment, section_size, next_section_offset)
            elif skip_data and section_type in ('sectors', 'table', 'table2'):
                logging.info(f"Skipping {section_type} section")
                input_segment.seek(next_section_offset)
            elif section_type == "sectors":
                chunk_sequence_number = parse_sectors_section(input_segment, section_size, next_section_offset,
                                                              chunk_sequence_number, chunk_process_queues)
            elif section_type == "table":
                parse_table_section(input_segment, section_size, next_section_offset)
            elif section_type == "table2":
                parse_table2_section(input_segment, section_size, next_section_offset)
            elif section_type == "data":
                parse_data_section(input_segment, section_size, next_section_offset)
            elif section_type == "digest":
                parse_digest_section(input_segment, section_size, next_section_offset)
            elif section_type == "hash":
                md5_hash = parse_hash_section(input_segment, section_size, next_section_offset)
            elif section_type == "done":
                logging.debug(f"End of image file.")
                result = (True, md5_hash)
                break
            elif section_type == "next":
                result = (False, None)
                break
            elif section_type in ("disk", "x_description", "x_hash", "x_statistics"):
                logging.info(f"Ignoring undocumented {section_type} section")
                input_segment.seek(next_section_offset)
            else:
                close_chunk_processors(chunk_process_queues, chunk_processors, writer_thread)
                raise ValueError(f"Unknown section_type: {section_type}")

    close_chunk_processors(chunk_process_queues, chunk_processors, writer_thread)
    return result


def close_chunk_processors(chunk_process_queues, chunk_processors, writer_thread):
    """
    Send stop on all queues and close processes and writer thread.
    :param chunk_process_queues:
    :param chunk_processors:
    :param writer_thread:
    :return:
    """
    for i in range(len(chunk_processors)):
        chunk_process_queues[i].put(None)
        chunk_processors[i].join()
    writer_thread.join()


def chunk_worker(input_queue: Queue, output_queue: Queue):
    """
    Worker for multiprocessing. Either decompress or validate the checksum depending on the compression flag in the job.
    The raw chunk data is set to the output queue.
    :param input_queue:
    :param output_queue:
    :return:
    """
    while True:
        job = input_queue.get()
        if job is None:
            output_queue.put(None)
            break

        compression, data = job
        if compression:
            output_queue.put(zlib.decompress(data))
        else:
            chunk_data = data[:-4]
            checksum = convert_bin_to_int(data[-4:])
            if zlib.adler32(chunk_data) != checksum:
                raise Exception(f"Checksum failure ({zlib.adler32(chunk_data)} != {checksum})")
            output_queue.put(chunk_data)


def file_writer(output_file, chunk_result_queues):
    """
    Read the chunk_result_queues round-robin to ensure the order of the chunks and write the result to the output_file.
    :param output_file:
    :param chunk_result_queues:
    :return:
    """
    i = 0
    while True:
        i += 1
        chunk = chunk_result_queues[i % len(chunk_result_queues)].get()
        if chunk is None:
            break
        output_file.write(chunk)


def parse_digest_section(input_e01, section_size, next_section_offset):
    """
    The digest section contains the MD5 and SHA1 hash of the imaged data. (image of raw data, not e01 files)
    :param input_e01:
    :param section_size:
    :param next_section_offset:
    :return:
    """
    print_hex_format(input_e01.read(16), "MD5 hash: ")
    print_hex_format(input_e01.read(20), "SHA1 hash: ")
    print_hex_format(input_e01.read(40), "padding: ")
    print_hex_format(input_e01.read(4), "checksum: ")


def parse_hash_section(input_e01, section_size, next_section_offset):
    """
    The hash section contains the MD5 hash of the imaged data. (image of raw data, not e01 files)
    :param input_e01:
    :param section_size:
    :param next_section_offset:
    :return:
    """
    md5_hash = input_e01.read(16)
    print_hex_format(md5_hash, "MD5: ")
    print_hex_format(input_e01.read(16), "padding: ")
    print_hex_format(input_e01.read(4), "checksum: ")
    return md5_hash


def parse_table2_section(input_e01, section_size, next_section_offset):
    """
    Inverse of the table section. Made for recovery purposes.
    :param input_e01:
    :param section_size:
    :param next_section_offset:
    :return:
    """
    input_e01.read(section_size - 76)
    logging.debug(f"Skipping {section_size - 76} bytes of table2 data")


def parse_data_section(input_e01, section_size, next_section_offset):
    """
    Section containing similar data as the volume section, but is placed in subsequent segments instead of the first.
    In images consisting of one segment the section is added to the first segment.
    :param input_e01:
    :param section_size:
    :param next_section_offset:
    :return:
    """
    # print_hex_format(input_e01.read(1), "media type: ")
    # print_hex_format(input_e01.read(3), "padding: ")
    # print_int(input_e01.read(4), "chunk count: ")
    # print_int(input_e01.read(4), "sectors per chunk: ")
    # print_int(input_e01.read(4), "bytes per sector: ")
    # print_int(input_e01.read(8), "sector count: ")
    # print_int(input_e01.read(4), "cylinder count: ")
    # print_int(input_e01.read(4), "heads count: ")
    # print_int(input_e01.read(4), "sectors C:H:S count: ")
    # print_hex_format(input_e01.read(1), "Media flags: ")
    # print_hex_format(input_e01.read(3), "padding: ")
    # print_int(input_e01.read(4), "PALM volume start sector: ")
    # print_hex_format(input_e01.read(4), "padding: ")
    # print_int(input_e01.read(4), "SMART logs start sector: ")
    # print_int(input_e01.read(1), "Compression level: ")
    # print_hex_format(input_e01.read(3), "padding: ")
    # print_int(input_e01.read(4), "sector error granularity: ")
    # print_hex_format(input_e01.read(4), "padding: ")
    # print_hex_format(input_e01.read(16), "Segment file set identifier: ")
    # print_hex_format(input_e01.read(963), "padding: ")
    # print_hex_format(input_e01.read(5), "Signature (0x00): ")
    # print_hex_format(input_e01.read(4), "checksum: ")
    input_e01.read(section_size - 76)
    logging.debug(f"Skipping {section_size - 76} bytes of data_section data")


def parse_sectors_section(input_e01, sectors_section_size, next_section_offset, chunk_sequence_number,
                          chunk_process_queues):
    """
    Read the data from the sectors section and write it to the output file. To read the sectors section, it is first
    skipped to read the table section which follows this section. It is parsed to obtain the necessary offsets to read
    the data chunks in this file.
    :param input_e01:
    :param sectors_section_size:
    :param next_section_offset:
    :param chunk_sequence_number: This is a sequence number generated to synchronise the chunks through the
    multiprocessing
    :param chunk_process_queues:  A list with a queue for every chunk_process. Jobs are assigned round-robin.
    :return:
    """
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
        chunk_sequence_number += 1
        compression = block_offsets[i][0]
        block_offset = block_offsets[i][1]
        if i < len(block_offsets) - 1:
            block_size = block_offsets[i + 1][1] - block_offset
        else:
            block_size = start_of_table_section - table_base_offset - block_offset

        if compression:
            print("ping")

        input_e01.seek(table_base_offset + block_offset, 0)
        data = input_e01.read(block_size)
        chunk_process_queues[chunk_sequence_number % len(chunk_process_queues)].put((compression, data))

    input_e01.seek(after_table_section, 0)
    return chunk_sequence_number


def parse_volume_section(input_e01, section_size, next_section_offset):
    """
    The volume section contains metadata on the imaged device.
    :param input_e01:
    :param section_size:
    :param next_section_offset:
    :return:
    """
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
    logging.debug(f"number of table entries: {entries_number}")
    print_hex_format(input_e01.read(4), "padding: ")
    table_base_offset = convert_bin_to_int(input_e01.read(8))
    logging.debug(f"table base offset: {table_base_offset}")
    print_hex_format(input_e01.read(4), "padding: ")
    print_hex_format(input_e01.read(4), "checksum: ")
    logging.debug(f"skipping {entries_number * 4} bytes of chunk offsets")
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
    """
    Read the section descriptor (the first 76 bytes of a section). The descriptor contains the section type, the offset
    from the beginning of the segment to the next section, the size of the data within the section and a checksum.
    :param input_e01:
    :return:
    """
    logging.debug(f"----------Section descriptor----------")
    descriptor_blob = input_e01.read(72)
    try:
        type_blob = descriptor_blob[0:16]
        section_type = convert_bin_to_text(type_blob).rstrip('\x00')
        logging.debug(f"type: {section_type}")
        next_section_offset_blob = descriptor_blob[16:24]
        print_int(next_section_offset_blob, "offset to next section: ")
        section_size_blob = descriptor_blob[24:32]
        print_int(section_size_blob, "section size: ")
        print_hex_format(descriptor_blob[32:72], "Padding: ")
        checksum = convert_bin_to_int(input_e01.read(4))
        if zlib.adler32(descriptor_blob) != checksum:
            logging.error(f"Error at {input_e01.tell()}")
            raise Exception(f"The checksum for the section descriptor is incorrect! ({zlib.adler32(descriptor_blob)} != {checksum}")
        return section_type, \
            convert_bin_to_int(next_section_offset_blob), \
            convert_bin_to_int(section_size_blob)
    except Exception as e:
        print_hex_format(descriptor_blob, print_method=logging.error)
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
    logging.debug(f"----------data----------")
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
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler()
        ]
    )
    input_path_main = r"/path/to/encase/image"
    output_path_main = r"/path/to/raw/image"
    start = datetime.now()
    logging.info(f"{start}: Start")
    convert_e01_to_dd(input_path_main, output_path_main, threads=1, skip_data=False, start_from_segment=6)
    logging.info(f"{datetime.now()}: Finished ({(datetime.now() - start).seconds} seconds)")
    logging.info(calculate_hash(output_path_main))
