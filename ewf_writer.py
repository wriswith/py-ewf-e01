import argparse
import logging

import math
import multiprocessing
import os
import time
import uuid
import zlib
from threading import Thread, Event

from binary_helper import convert_int_to_bin
from datetime import datetime
from binary_helper import pad_bytes
from compressed_file_reader import CompressedReader
from input_types import GenericInputFile, DDInputFile, BinInputFile
from print_helper import print_hex_format


def create_segment_file(output_path, sequence_number):
    """
    Creates a new file object with the path "output_path". Currently, there is no automatic modification of the
    extension. The segment header will be written to the file and the open file object will be returned.
    :param output_path:
    :param sequence_number:
    :return:
    """
    # TODO: calculate correct extension if sequence_number is not 1
    segment_file = open(output_path, "wb+", buffering=100 * 1024 * 1024)
    segment_file.write(b'\x45\x56\x46\x09\x0d\x0a\xff\x00\x01')  # Static signature + static start of field
    segment_file.write(convert_int_to_bin(sequence_number, number_of_bytes=2))
    segment_file.write(b'\x00\x00')  # Static end of fields
    return segment_file


def write_dummy_header2_section(segment_file, acquisition_time):
    """
    Writes metadata to the image that should be provided by the operator. This section is not implemented and dummy
    data was taken from a sample image. Only the acquisition time is implemented.
    :param segment_file:
    :param acquisition_time:
    :return:
    """
    uncompressed_data = b'\xff\xfe'
    # lines taken from a test image with most values cleared out
    lines = ['3', 'main', 'a\tctn\te\tt\tmd\tsn\tav\tov\tm\tu\tp\tdc',
             f'description\t\t\t\t\t\t\t\t\t{acquisition_time}\t{acquisition_time}\t0\t',
             '', 'srce', '0\t1', 'p\tn\tid\tev\ttb\tlo\tpo\tah\tgu\taq', '0\t0',
             '\t\t\t\t\t-1\t-1\t\t\t', '', 'sub', '0\t1', 'p\tn\tid\tnu\tco\tgu',
             '0\t0', '\t\t\t\t1\t', '']
    uncompressed_data += ('\n'.join(lines) + '\n').encode('utf-16-le')
    compressed_data = zlib.compress(uncompressed_data, level=5)
    write_section_descriptor(segment_file, 'header2', len(compressed_data))
    segment_file.write(compressed_data)


def write_dummy_header_section(segment_file, acquisition_time):
    """
    Writes metadata to the image that should be provided by the operator. This section is not implemented and dummy
    data was taken from a sample image. Only the acquisition time is implemented.
    :param segment_file:
    :param acquisition_time:
    :return:
    """
    dt_object = datetime.fromtimestamp(acquisition_time)
    formatted_time = dt_object.strftime('%Y %m %d %H %M %S')

    # lines taken from a test image with most values cleared out
    lines = ['1', 'main', 'c\tn\ta\te\tt\tav\tov\tm\tu\tp',
             f'\t\tdescription\t\t\t\tPython\t{formatted_time}\t{formatted_time}\t0', '']
    uncompressed_data = ('\n'.join(lines) + '\n').encode('ASCII')
    compressed_data = zlib.compress(uncompressed_data, level=5)
    write_section_descriptor(segment_file, 'header', len(compressed_data))
    segment_file.write(compressed_data)


def write_section_descriptor(segment_file, section_type, data_length):
    """
    Write the header for this section. This header contains the section_type, the offset of the start of the next
    section, the total size of this section and a checksum of this header.
    :param segment_file:
    :param section_type: String containing the section_type.
    :param data_length: Length of the data in this section excluding the header.
    :return:
    """
    offset_start_of_section = segment_file.tell()
    section_descriptor_blob = pad_bytes(section_type.encode('ascii'), 16)  # Add section type
    if section_type in ("done", "next"):
        # Set offset to the next section to start of this section for the done and next section as they are always the
        # last section in a segment file
        section_descriptor_blob += convert_int_to_bin(offset_start_of_section, 8)
    else:
        section_descriptor_blob += convert_int_to_bin(offset_start_of_section + 76 + data_length,
                                                      8)  # Add offset next section
    section_descriptor_blob += convert_int_to_bin(76 + data_length, 8)  # add section size
    section_descriptor_blob += b'\x00' * 40
    section_descriptor_blob += convert_int_to_bin(zlib.adler32(section_descriptor_blob), 4)  # Add checksum
    segment_file.write(section_descriptor_blob)


def get_volume_metadata(input_file_object: GenericInputFile, image_guid):
    """
    This function creates a dict with technical metadata concerning the image. An import value which is set here is the
    sectors per chunk. The data is compressed per chunk, which is the smallest unit readable in an e01-file. A higher
    amount of sectors per chunk makes the creation of the e01 more efficient, but might cause performance issues when
    using the image in cases of many small random reads. The default value used by most tools is 64 sectors per chunk.
    This code uses 256 sectors per chunk as it causes an 300% speed increase creating the image.
    :param input_file_object:
    :param image_guid:
    :return:
    """
    # TODO: choose how to configure the sectors_per_chunk. The default 64 causes performance problems on NVMe storage.
    #       256 seems more sensible.
    volume_metadata = {
        # 'sectors_per_chunk': 64,
        'sectors_per_chunk': 256,
        'bytes_per_sector': 512,
        'media_flags': b'\x03',
        'compression_level': 1,
        'sector_error_granularity': 64,
        'image_guid': image_guid
    }
    source_size = input_file_object.get_size()
    volume_metadata['sector_count'] = int(source_size / volume_metadata['bytes_per_sector'])
    volume_metadata['chunk_count'] = math.ceil(volume_metadata['sector_count'] / volume_metadata['sectors_per_chunk'])
    return volume_metadata


def write_volume_section(segment_file, volume_metadata):
    """
    Write the section with technical metadata to the image file. This section is only written to the first segment file.
    :param segment_file:
    :param volume_metadata:
    :return:
    """
    volume_section = format_volume_metadata(volume_metadata)
    write_section_descriptor(segment_file, "volume", len(volume_section))
    segment_file.write(volume_section)


def format_volume_metadata(volume_metadata):
    """
    Format the volume metadata and return a bytestring which can be used in volume and data sections.
    :param volume_metadata:
    :return:
    """
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


def sector_receiver(sectors: list, input_file: CompressedReader, sectors_written_trigger: Event,
                    sectors_received_trigger: Event):
    """
    Helper function to put the receiving of data from the compression processes in a separate thread. This thread
    communicates with the main thread via the sectors list.
    To prevent high memory usage in case of slow writing performance, the thread will sleep if the sectors list is too
    large.
    :param sectors:
    :param input_file:
    :param sectors_written_trigger:
    :param sectors_received_trigger:
    :return:
    """
    i = 0
    while True:
        # If there are too many chunks waiting to be written to disk, pause for 1 second or until the main thread
        # signals to check again.
        i += 1
        if i % 100000 == 0:
            sectors_written_trigger.clear()
            while len(sectors) > 20000:
                sectors_written_trigger.wait(1)

        if i % 1000 == 0 and not sectors_received_trigger.is_set():
            sectors_received_trigger.set()

        # Receive chunk from reader object
        chunk = input_file.read_chunk()
        sectors.append(chunk)
        if chunk is None:
            break


def write_sectors_section(segment_file, input_file_object: GenericInputFile, volume_metadata,
                          number_of_compression_threads):
    """
    This function will read the contents of the source file and write is to the destination image. It might write
    multiple sectors sections for this, as there are constraints which limit the size of a sectors section. For every
    sectors section a table section is written containing the offset of every chunk (of source data) that is stored in
    the preceding sectors section.
    To achieve high preforming interprocess communication all communication between processes is handled in separate
    threads. There is one process to read the source file, one process to calculate the MD5 hash,
    "number_of_compression_threads" to compress the data and the main process which writes the output to disk.
    :param segment_file: File object for the output file
    :param input_file_object: Path to the input file
    :param volume_metadata: Dict with technical metadata
    :param number_of_compression_threads: Number of processes to spawn to compress chunks.
    :return: Returns the MD5-hash of the source file
    """
    # Calculate the size of the datachunks based on the values chosen in the volume_metadata
    chunk_size = volume_metadata['sectors_per_chunk'] * volume_metadata['bytes_per_sector']

    # Initialize an array to communicate the MD5 hash from the calculating process to this process.
    md5_hash_array = multiprocessing.Array('c', 32)

    # Create an object to read the data. This object will spawn the compression and hashing processes.
    input_file = CompressedReader(input_file_object, number_of_compression_threads, chunk_size, md5_hash_array)

    # Set up a thread to receive the data from the compressed reader object
    sectors = []
    sectors_written_trigger = Event()
    sectors_received_trigger = Event()
    file_reader_thread = Thread(target=sector_receiver, args=(sectors, input_file, sectors_written_trigger,
                                                              sectors_received_trigger), daemon=True)
    file_reader_thread.start()

    # Iterate over the processed chunks and write them to the output file
    chunks_written = 0
    image_complete = False
    start = datetime.now()
    while not image_complete:
        # Add a new sectors section. There might be several sectors sections depending on the size of the image.
        start_of_section = segment_file.tell()
        table_base_offset = start_of_section
        # Write an empty descriptor as we need to write the data first before we can calculate get the section length
        segment_file.write(b'\x00' * 76)
        start_of_sectors_data = segment_file.tell()

        chunk_offsets = []  # Store the offset of every chunk for the table section
        while True:
            # calculate the offset of the chunk relative to the start of the sectors section instead of start of file
            # (due to a four byte size offset size constraint (4 bytes minus one bit as flag for compression))
            offset = segment_file.tell() - table_base_offset

            if offset > 0x7FFFFFFF:
                break  # The max offset was reached by the previous chunk. The sectors section is full.

            # Wait for data from the data receiver thread.
            if len(sectors) == 0:
                sectors_received_trigger.clear()
                while len(sectors) == 0:
                    sectors_received_trigger.wait(1)
            chunk = sectors.pop(0)

            # A None value will be pushed to signal the end of image.
            if chunk is None:
                image_complete = True
                break

            uncompressed_chunk, compressed_chunk = chunk

            # If the uncompressed chunk is smaller than the compressed chunk, the uncompressed value is written
            if compressed_chunk is None:
                segment_file.write(uncompressed_chunk)

            # If the compressed value is used, the most significant bit off the offset is set to 1
            else:
                offset = offset | 0x80000000  # Set the MSB to 1 to set the compression flag
                segment_file.write(compressed_chunk)

            # Add offset to list so it can be written to the table section
            chunk_offsets.append(convert_int_to_bin(offset, 4))

            chunks_written += 1
            # Periodically check if the data receiver thread paused.
            if chunks_written % 1000 == 0 and not sectors_written_trigger.is_set():
                sectors_written_trigger.set()

            # Print speed and progress information.
            if chunks_written % 10000 == 0:
                total_megabyte_written = chunks_written * chunk_size / 1024 / 1024
                logging.info(f'{datetime.now()}: Finished {total_megabyte_written} MB, '
                             f'{"{0:.2f}".format(total_megabyte_written / 1024 / ((datetime.now() - start).seconds / 60))} GB/min) '
                             f'{"{0:.2f}".format(total_megabyte_written / (datetime.now() - start).seconds)} MB/sec).')

        # Finish the last sectors section by writing the section descriptor
        end_of_section = segment_file.tell()
        segment_file.seek(start_of_section)
        write_section_descriptor(segment_file, "sectors", end_of_section - start_of_sectors_data)
        segment_file.seek(end_of_section)

        # Write table and table2 section
        write_table_section(segment_file, table_base_offset, chunk_offsets)

    while md5_hash_array.value == b'\x00' * 32 or len(md5_hash_array.value) != 16:
        time.sleep(0.1)
    return md5_hash_array.value


def write_table_section(segment_file, table_base_offset, chunk_offsets):
    """
    Write table section to segment_file. This section contains the offsets for the start of every chunk in the preceding
    sectors section.
    :param segment_file:
    :param table_base_offset:
    :param chunk_offsets:
    :return:
    """
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
    """
    Write the data section to the image file. This section is near identical to the volume section. This section is
    written to all segments, except the first one. If there is only one segment, this section is added near the end of
    segment file.
    :param segment_file:
    :param volume_metadata:
    :return:
    """
    volume_section = format_volume_metadata(volume_metadata)
    write_section_descriptor(segment_file, "data", len(volume_section))
    segment_file.write(volume_section)


def write_digest_section(segment_file, md5_hash, sha1_hash):
    """
    The digest section contains the md5 and sha1 hashes of the source file. This enables for example X-Ways to validate
    the integrity of the image.
    This section is not used by the script as calculating both the md5 and the sha1 takes too much time. Only the hash
    section is used.
    :param segment_file:
    :param md5_hash:
    :param sha1_hash:
    :return:
    """
    write_section_descriptor(segment_file, 'digest', 80)
    digest_data = md5_hash
    digest_data += sha1_hash
    digest_data += b'\x00' * 40
    segment_file.write(digest_data)
    segment_file.write(convert_int_to_bin(zlib.adler32(digest_data), 4))


def write_hash_section(segment_file, md5_hash):
    """
    The hash section contains the md5 hash of the source file. This enables for example X-Ways to validate the integrity
     of the image.
    :param segment_file:
    :param md5_hash:
    :return:
    """
    write_section_descriptor(segment_file, 'hash', 36)
    hash_data = bytes(md5_hash)
    if len(hash_data) != 16:
        print_hex_format(md5_hash, 'md5_hash error:', logging.error)
        print_hex_format(hash_data, 'hash error:', logging.error)
        raise ValueError(f"Hash is not the right length.")
    print_hex_format(hash_data, label='hash_data: ', print_method=logging.error)
    hash_data += b'\x00' * 16
    print_hex_format(hash_data, label='hash_data: ', print_method=logging.error)
    segment_file.write(hash_data)
    segment_file.write(convert_int_to_bin(zlib.adler32(hash_data), 4))


def write_done_section(segment_file):
    """
    This section signals the end of the last segment file in the image.
    :param segment_file:
    :return:
    """
    write_section_descriptor(segment_file, 'done', 0)


def write_next_section(segment_file):
    """
    This section signals the end of the current segment file, but also that there is a subsequent segment that should be
     read.
    :param segment_file:
    :return:
    """
    write_section_descriptor(segment_file, 'next', 0)


def convert_raw_to_e01(input_file_object: GenericInputFile, output_path, number_of_compression_threads=3):
    # Generate random guid which is the unique identifier which will be stored in the image metadata
    image_guid = uuid.uuid4().hex[0:16].encode("ASCII")
    acquisition_time = int(time.time())

    # create the first segment file (.e01). A segment file is made up of sections which contain metadata or imagedata.
    segment_file = create_segment_file(output_path, 1)

    # generate empty header2 and header. Normally this contains metadata like case-number and operator. The only
    # metadata implemented is the acquisition time which is the timestamp this script was run.
    write_dummy_header2_section(segment_file, acquisition_time)
    write_dummy_header_section(segment_file, acquisition_time)

    # Get metadata about the image and set technical metadata. These values are used in the volume & data section
    volume_metadata = get_volume_metadata(input_file_object, image_guid)
    logging.debug(volume_metadata)

    # write volume section which technical metadata
    write_volume_section(segment_file, volume_metadata)

    # Read in the source file and write the actual data to destination image.
    md5_hash = write_sectors_section(segment_file, input_file_object, volume_metadata, number_of_compression_threads)
    logging.debug(f"md5_hash: {md5_hash}")

    # Write data section (contains the same info as the volume section)
    # Todo: Only write this at end of file if this is the image has only one segment
    write_data_section(segment_file, volume_metadata)

    # The digest section is not written as calculating the sha1 hash has too much of a performance impact on the script.
    # write_digest_section(segment_file, md5_hash, sha1_hash)

    # Write hash section. This section contains the md5 hash of the source file.
    write_hash_section(segment_file, md5_hash)

    # Write the done section to signal that there are no more segment files in this image
    write_done_section(segment_file)
    segment_file.close()


def convert_raw_to_e01_wrapper():
    parser = argparse.ArgumentParser(prog='EWF Writer', description='This program reads an image in raw format and '
                                                                    'converts in into an e01 encase image.')
    parser.add_argument('-i', '--input_path', required=True, help="Path to the raw image. If this path "
                                                                  "points to a file, a raw image consisting of one file is assumed. If this path points to a "
                                                                  "folder, a segmented raw image is assumed.")
    parser.add_argument('-e', '--input_file_extension', default=".bin", help="Optional parameter to be "
                                                                             "used if the input files do not have a .bin extension.")
    parser.add_argument('-o', '--output_path', required=True, help="Path to the outputfile.")
    parser.add_argument('-t', '--threads', default=3, help="Number of cores used for compression.")

    args = parser.parse_args()

    if os.path.isdir(args.input_path):
        input_file_object = BinInputFile(args.input_path, extension=args.input_file_extension)
    else:
        input_file_object = DDInputFile(args.input_path)
    start_main = datetime.now()

    logging.info(f"{datetime.now()}: Start")
    convert_raw_to_e01(input_file_object, args.output_path, int(args.threads))
    logging.info(f"{datetime.now()}: Finished ({(datetime.now() - start_main).seconds} seconds)")


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler()
        ]
    )

    multiprocessing.freeze_support()
    convert_raw_to_e01_wrapper()
