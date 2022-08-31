from multiprocessing import Process, Queue
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, IPPROTO_TCP, TCP_NODELAY

import logging
import sys
import time

from roast import pre_round, sign_round
from transport import send_obj, recv_obj

MAX_NONCE_QUEUE = 32

class Participant:
    def __init__(self, X, i, sk_i, nonce_queue):
        self.X = X
        self.i = i
        self.sk_i = sk_i
        self.nonce_queue = nonce_queue
        self.spre_i, self.pre_i = nonce_queue.get()

    def sign_round(self, msg, T, pre):
        s_i = sign_round(self.X, msg, T, pre, self.i, self.sk_i, self.spre_i)
        self.spre_i, self.pre_i = self.nonce_queue.get()
        return s_i, self.pre_i

def handle_requests(connection, nonce_queue):
    curr_run_id = -1

    while True:
        obj = recv_obj(connection)
        if obj is None:
            logging.debug('Connection closed')
            break

        run_id, data = obj
        if run_id < curr_run_id:
            logging.debug(f'Participant {i}: Ignoring incoming message from outdated run (run_id = {run_id}, curr_run_id = {curr_run_id})')
        elif run_id > curr_run_id:
            X, i, sk_i = data
            logging.debug(f'Participant {i}: Received initialization data for new run (run_id = {run_id}, curr_run_id = {curr_run_id})')
            curr_run_id = run_id
            participant = Participant(X, i, sk_i, nonce_queue)
            send_obj(connection, (run_id, (i, None, participant.pre_i)))
            logging.debug(f'Participant {i}: Sent initial pre_i value')
        else:
            msg, T, pre, is_malicious = data
            logging.info(f'Participant {i}: Received sign_round request, run_id = {run_id}, is_malicious = {is_malicious}')
            if not is_malicious:
                start = time.time()
                s_i, pre_i = participant.sign_round(msg, T, pre)
                elapsed = time.time() - start
                send_obj(connection, (run_id, (i, s_i, pre_i)))
                logging.info(f'Participant {i}: Sent sign_round response and next pre_i value in {elapsed:.4f} seconds')

def compute_nonce_loop(nonce_queue):
    while True:
        nonce_queue.put(pre_round())

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <port>')
        sys.exit(1)

    nonce_queue = Queue(MAX_NONCE_QUEUE)
    Process(target=compute_nonce_loop, args=[nonce_queue], daemon=True).start()

    port = int(sys.argv[1])
    addr = ('0.0.0.0', port)

    sock = socket(AF_INET, SOCK_STREAM)
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, True)
    sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, True)
    sock.bind(addr)
    sock.listen()

    while True:
        logging.debug(f'Listening for incoming connections on {addr}')

        connection, src = sock.accept()
        logging.debug('Accepted connection from {src}')

        try:
            handle_requests(connection, nonce_queue)
        except ConnectionResetError as e:
            print(e)
