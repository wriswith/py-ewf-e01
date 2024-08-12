import threading
import time
import zlib
from multiprocessing import Process, Pipe, Value, Array, Event
from threading import Thread

from binary_helper import convert_int_to_bin
from input_types import GenericInputFile
from thread_communication_helper import data_receiver, data_sender, multiple_data_sender
from verify_hash import calculate_md5_worker, calculate_sha1_worker


class CompressedReader:
    """
    This object will read the contents of the provided GenericInputFile object. The contents will be compressed and
    provided through the read_chunk function for writing to e01-files.
    """
    def __init__(self, input_file_object: GenericInputFile, number_of_threads, chunk_size, md5_hash_array: Array):
        """
        Initialize the object and start the read, hashing en compression processes.
        :param input_file_object: This object should be a child of the GenericInputFile object.
        :param number_of_threads: The number of compression processes that will be created.
        :param chunk_size: The size of chunk to read and compress.
        :param md5_hash_array: Return value to communicate the md5 hash of the data read after receiving an EOF.
        """
        self.input_file_object = input_file_object
        self.number_of_threads = number_of_threads
        self.chunk_size = chunk_size

        # Integer to track which chunks have been returned to the main function.
        self.next_sequence = 0
        # Value to periodically communicate the next_sequence to the reader process. This allows the reading of data to
        # be paused to avoid memory issues.
        self.read_retarder_sequence_number = Value('i', 0)
        self.read_retarder_sequence_changed = Event()

        # Pipes to communicate to the compression and hashing processes.
        self.compression_send_pipes = []
        self.compression_recv_pipes = []
        md5_send_pipes = []
        md5_rcv_pipes = []
        for i in range(number_of_threads):
            send, recv = Pipe()
            self.compression_send_pipes.append(send)
            self.compression_recv_pipes.append(recv)
            md5_pipe_send, md5_pipe_rcv = Pipe()
            md5_send_pipes.append(md5_pipe_send)
            md5_rcv_pipes.append(md5_pipe_rcv)

        # Pipes to receive data from the compression threads
        self.result_send_pipes = []
        self.result_recv_pipes = []
        for i in range(number_of_threads):
            send, recv = Pipe()
            self.result_send_pipes.append(send)
            self.result_recv_pipes.append(recv)

        # Start process to hash the data read by the file_reader process.
        self.md5_worker = Process(target=calculate_md5_worker, args=(md5_rcv_pipes, md5_hash_array))
        self.md5_worker.start()

        # Start process to read the data from file and send it to the compression processes..
        file_reader_process = Thread(target=file_reader, args=(self.input_file_object,
                                                               self.compression_send_pipes,
                                                               self.chunk_size,
                                                               self.number_of_threads,
                                                               self.read_retarder_sequence_number,
                                                               self.read_retarder_sequence_changed,
                                                               (md5_send_pipes, )
                                                               ), daemon=True
                                     )
        file_reader_process.start()
        # Start the compression processes.
        for i in range(self.number_of_threads):
            chunk_compressor_process = Process(target=chunk_compressor,
                                               args=(self.compression_recv_pipes[i], self.result_send_pipes[i])
                                               )
            chunk_compressor_process.start()

    def read_chunk(self):
        """
        Function to receive a chunk which has been read from file and has been processed by the compression processes.
        The next_sequence is used to determine which compression process provides the next chunk of data.
        At the end of the file None is returned.
        :return:
        """
        result = self.result_recv_pipes[self.next_sequence % self.number_of_threads].recv()
        if result is None:
            for i in range(self.number_of_threads - 1):
                self.next_sequence += 1
                self.result_recv_pipes[self.next_sequence % self.number_of_threads].recv()
            return None

        self.next_sequence += 1

        # Periodically sync the next_sequence value with the other process, so it can pause reading if it is too far
        # ahead.
        if self.next_sequence % 1000:
            self.read_retarder_sequence_number.value = self.next_sequence
            self.read_retarder_sequence_changed.set()

        uncompressed_chunk, compressed_chunk = result
        return uncompressed_chunk, compressed_chunk


def file_reader(input_file: GenericInputFile, compression_pipes: [Pipe], chunk_size, number_of_threads,
                read_retarder_sequence_number: Value, read_retarder_sequence_changed: Event, hashing_pipes):
    """
    Read the data chunks from the input_file and send it to the hashing processes and to the correct compression
    process.
    :param input_file:
    :param compression_pipes:
    :param chunk_size:
    :param number_of_threads:
    :param read_retarder_sequence_number:
    :param read_retarder_sequence_changed:
    :param hashing_pipes:
    :return:
    """
    jobs = []  # List to send data to the pipes in a separate thread.
    data_sender_threads = []  # Threads to communicate with the other processes.
    data_ready_to_send_events = []

    # Set up a thread for every compression process to communicate with that specific process without slowing down the
    # reading of data.
    for i in range(number_of_threads):
        jobs.append([])
        pipes = [compression_pipes[i], ]
        for j in range(len(hashing_pipes)):
            pipes.append(hashing_pipes[j][i])
        data_ready_to_send_events.append(threading.Event())
        data_sender_threads.append(Thread(target=multiple_data_sender, args=(pipes, jobs[i],
                                                                             data_ready_to_send_events[i]), daemon=True)
                                   )
        data_sender_threads[i].start()

    input_file.open()
    try:
        sequence_number = 0
        while True:
            # Periodically check that the file_reader is not too far ahead of the rest of the program.
            if sequence_number % 3000 and read_retarder_sequence_number.value < sequence_number - 40000:
                read_retarder_sequence_changed.clear()
                while read_retarder_sequence_number.value < sequence_number - 40000:
                    read_retarder_sequence_changed.wait(1)

            if sequence_number % 1000 == 0:
                for event in data_ready_to_send_events:
                    event.set()

            uncompressed_chunk = input_file.read(chunk_size)

            # At the end of file send None to every compression communication thread to end the thread
            if len(uncompressed_chunk) == 0:
                for i in range(number_of_threads):
                    jobs[i].append(None)
                break

            # Communicate the chunk to the correct compression thread.
            pipe_number = sequence_number % number_of_threads
            jobs[pipe_number].append(uncompressed_chunk)
            sequence_number += 1
    except Exception as e:
        raise e
    finally:
        input_file.close()

    # Finish all the threads communication threads.
    for data_sender_thread in data_sender_threads:
        data_sender_thread.join()

    # Finish all the compression and hashing processes.
    for compression_pipe in compression_pipes:
        compression_pipe.send(None)
    for pipes in hashing_pipes:
        for pipe in pipes:
            pipe.send(None)


def chunk_compressor(compression_pipe: Pipe, result_pipe: Pipe):
    """
    Function to compress the chunks that have been read by the file_reader process. Either the uncompressed or the
    compressed chunk is returned, depending on which is the smallest.
    :param compression_pipe: Input pipe to provide uncompressed chunks.
    :param result_pipe: Result pipe to return processed chunks.
    :return:
    """
    # Set up communication threads to offload interprocess communication
    uncompressed_chunks = []
    results = []
    data_ready_to_receive = threading.Event()
    data_receiver_thread = Thread(target=data_receiver, args=(compression_pipe, uncompressed_chunks,
                                                              data_ready_to_receive), daemon=True)
    data_receiver_thread.start()
    data_ready_to_send = threading.Event()
    data_sender_thread = Thread(target=data_sender, args=(result_pipe, results, data_ready_to_send), daemon=True)
    data_sender_thread.start()

    i = 0
    while True:
        # Sleep when done waiting for new data/
        if len(uncompressed_chunks) == 0:
            data_ready_to_receive.clear()
            while len(uncompressed_chunks) == 0:
                data_ready_to_receive.wait(1)

        uncompressed_chunk = uncompressed_chunks.pop(0)

        # If reading of file is done, communicate end to result threads and break the loop
        if uncompressed_chunk is None:
            results.append(None)
            break

        # Compress the chunk with zlib.
        compressed_chunk = zlib.compress(uncompressed_chunk, level=5)
        compressed_chunk_len = len(compressed_chunk)

        if len(uncompressed_chunk) < compressed_chunk_len:
            # If the uncompressed_chunk is smaller, add a checksum to it and return the uncompressed chunk.
            checksum = convert_int_to_bin(zlib.adler32(uncompressed_chunk), 4)
            uncompressed_chunk = uncompressed_chunk + checksum
            results.append((uncompressed_chunk, None))
        else:
            # If the compressed chunk is smaller, return the compressed chunk
            results.append((None, compressed_chunk))

        i += 1
        if i % 1000 and not data_ready_to_send.is_set():
            data_ready_to_send.set()

    # Wait for all threads to finish.
    data_sender_thread.join()
    data_sender_thread.join()
