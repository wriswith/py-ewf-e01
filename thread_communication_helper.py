import time
from multiprocessing import Pipe
from threading import Event


def multiple_data_sender(pipes, jobs, data_ready_to_send_event: Event):
    """
    Helper function to move communication with other processes to a separate thread. The function reads data from the
    jobs list until it receives a None value to signal the end of the data. Every job will be pushed to every pipe in
    the pipes list.
    :param pipes:
    :param jobs:
    :param data_ready_to_send_event:
    :return:
    """
    while True:
        if len(jobs) == 0:
            data_ready_to_send_event.clear()
            while len(jobs) == 0:
                data_ready_to_send_event.wait(1)
        job = jobs.pop(0)
        if job is None:
            break
        else:
            for pipe in pipes:
                pipe.send(job)


def data_sender(pipe: Pipe, jobs: list, data_ready_to_send: Event):
    """
    Helper function to move communication with another process to a separate thread. The function reads data from the
    jobs list until it receives a None value to signal the end of the data. Every job will be pushed to the provided
    pipe.
    :param pipe:
    :param jobs:
    :param data_ready_to_send:
    :return:
    """
    while True:
        if len(jobs) == 0:
            data_ready_to_send.clear()
            while len(jobs) == 0:
                data_ready_to_send.wait(1)
        data = jobs.pop(0)
        pipe.send(data)
        if data is None:
            break


def data_receiver(pipe: Pipe, data_received: list, data_ready_to_receive: Event):
    """
    Helper function to move the receiving of data from another process to a separate thread. The function reads data
    from the pipe and puts it into the data_received list. A None value signals the end of data.
    :param pipe:
    :param data_received:
    :param data_ready_to_receive:
    :return:
    """
    i = 0
    while True:
        data = pipe.recv()
        data_received.append(data)
        if data is None:
            break
        i += 1
        if i % 1000 and not data_ready_to_receive.is_set():
            data_ready_to_receive.set()

