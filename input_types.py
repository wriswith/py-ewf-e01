import glob
import os


class GenericInputFile:
    """
    Generic object to allow inheritance to specific input file objects.
    """
    def __init__(self):
        pass

    def open(self):
        """
        Allows for the opening of the file for reading
        :return:
        """
        pass

    def read(self, chunk_size):
        """
        Allows for the reading of chunk_size bytes of data. If there is no more data to read None will be returned.
        :param chunk_size:
        :return:
        """
        pass

    def close(self):
        """
        Allows for the closing of the file.
        :return:
        """
        pass

    def get_size(self):
        """
        Calculates the total number of bytes for the file.
        :return:
        """
        pass


class DDInputFile (GenericInputFile):
    """
    InputFile object for monolithic raw files.
    """
    def __init__(self, input_path):
        super().__init__()
        self.input_path = input_path
        self.input_file = None

    def open(self):
        self.input_file = open(self.input_path, 'rb')

    def read(self, chunk_size):
        return self.input_file.read(chunk_size)

    def close(self):
        self.input_file.close()

    def get_size(self):
        return os.path.getsize(self.input_path)


class BinInputFile (GenericInputFile):
    """
    InputFile object for raw files that have been split into chunks.
    """
    def __init__(self, input_folder, extension='bin'):
        super().__init__()
        if extension[0] == '.':
            extension = extension[1:]
        self.input_paths = glob.glob(os.path.join(input_folder, f'*.{extension}'))
        self.input_paths.sort()
        self.total_size = calculate_total_size(self.input_paths)

        if len(self.input_paths) == 0:
            raise ValueError(f"The inputfolder does not contain any BIN-files.")
        self.input_file = None

    def open(self):
        self.input_file = open(self.input_paths.pop(0), 'rb')

    def read(self, chunk_size):
        chunk = self.input_file.read(chunk_size)
        if chunk is None:
            if len(self.input_paths) > 0:
                self.input_file.close()
                self.input_file = open(self.input_paths.pop(0), 'rb')
                chunk = self.input_file.read(chunk_size)
            else:
                return None

        if len(chunk) < chunk_size and len(self.input_paths) > 0:
            self.input_file.close()
            self.input_file = open(self.input_paths.pop(0), 'rb')
            chunk += self.input_file.read(chunk_size - len(chunk))

        return chunk

    def close(self):
        self.input_file.close()

    def get_size(self):
        return self.total_size


def calculate_total_size(files):
    """
    Calculate the total size of the given files.
    :param files: List of file paths
    :return: Total size in number of bytes
    """
    total_size = 0
    for file_path in files:
        total_size += os.path.getsize(file_path)
    return total_size

