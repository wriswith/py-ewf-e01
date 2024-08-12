import hashlib
import time
from multiprocessing import Pipe, Array
from threading import Thread, Event

from thread_communication_helper import data_receiver


def calculate_md5_worker(data_pipes: [Pipe], return_value: Array):
    md5_calculator = hashlib.md5()
    if len(data_pipes) == 0:
        return_value.value = md5_calculator.digest()
        return

    data_received = []
    data_receiver_treads = []
    data_ready_to_receive_events = []
    for i in range(len(data_pipes)):
        data_received.append([])
        data_ready_to_receive_events.append(Event())
        data_receiver_treads.append(Thread(target=data_receiver, args=(data_pipes[i], data_received[i],
                                                                       data_ready_to_receive_events[i]), daemon=True))
        data_receiver_treads[i].start()

    has_more_data = True
    while has_more_data:
        for i in range(len(data_pipes)):
            if len(data_received[i]) == 0:
                data_ready_to_receive_events[i].clear()
                while len(data_received[i]) == 0:
                    data_ready_to_receive_events[i].wait(1)

            chunk = data_received[i].pop(0)
            if chunk is None:
                has_more_data = False
                break
            else:
                md5_calculator.update(chunk)
    return_value.value = md5_calculator.digest()

    for data_receiver_tread in data_receiver_treads:
        data_receiver_tread.join()


def calculate_sha1_worker(data_pipe: Pipe, return_value: Array):
    sha1_calculator = hashlib.sha1()
    while True:
        chunk = data_pipe.recv()
        if chunk is None:
            break
        else:
            sha1_calculator.update(chunk)
    return_value.value = sha1_calculator.digest()


def calculate_hash(input_file_path):
    with open(input_file_path, 'rb') as input_file:
        return hashlib.md5(input_file.read()).hexdigest()
