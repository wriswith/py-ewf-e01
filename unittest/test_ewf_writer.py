import hashlib
import logging
import os
import sys
import time
from unittest import TestCase

from ewf_reader import convert_e01_to_dd
from ewf_writer import convert_raw_to_e01_wrapper
from verify_hash import calculate_hash


class Test(TestCase):
    def test_convert_raw_to_e01_wrapper(self):
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                            handlers=[logging.StreamHandler()])
        ewf_writer_input_file = self.generate_test_image()
        ewf_writer_output_file = f"{ewf_writer_input_file}.e01"
        ewf_reader_output_file = "unit_testing_convert_e01_to_dd.dd"

        # Set arguments for raw to e01
        sys.argv = [sys.argv[0]]
        sys.argv.extend(('-i', ewf_writer_input_file))
        sys.argv.extend(('-o', ewf_writer_output_file))
        sys.argv.extend(('-t', "1"))

        # Convert the test image
        convert_raw_to_e01_wrapper()

        # Convert the new e01 back to dd
        md5_hash_in_e01 = convert_e01_to_dd(ewf_writer_output_file, ewf_reader_output_file)

        # Verify the hashes
        md5_hash_in_e01 = md5_hash_in_e01.hex()
        md5_writer_input_file = calculate_hash(ewf_writer_input_file)
        self.assertEqual(md5_hash_in_e01, md5_writer_input_file)
        md5_reader_output_file = calculate_hash(ewf_reader_output_file)
        self.assertEqual(md5_hash_in_e01, md5_reader_output_file)

        time.sleep(1)
        # Cleanup if tests were successful
        os.remove(ewf_writer_input_file)
        os.remove(ewf_writer_output_file)
        os.remove(ewf_reader_output_file)

    @staticmethod
    def generate_test_image():
        test_file_name = "test_image_unit_testing.dd"
        data = []
        # Generate data
        for i in range(1000000):
            data.append(f"Line {i}".encode('ascii'))
        # Generate data that compresses poorly.
        for i in range(1000000):
            data.append(hashlib.md5(f"Line {i}".encode('ascii')).digest())
        data = b''.join(data)
        data += b'\x00' * (512 - (len(data) % 512))
        print(len(data))
        with open(test_file_name, 'wb') as test_file:
            test_file.write(data)
        return test_file_name
