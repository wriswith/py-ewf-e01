import hashlib


def calculate_hash(input_file):
    return hashlib.md5(open(input_file, 'rb').read()).hexdigest()
