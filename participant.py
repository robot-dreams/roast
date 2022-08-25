from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, IPPROTO_TCP, TCP_NODELAY

import logging
import sys
import time

from roast import pre_round, sign_round
from transport import send_obj, recv_obj

class NonceCache:
    def precompute(self, k):
        self.cached = []
        for i in range(k):
            self.cached.append(pre_round())

    def get(self):
        if len(self.cached) == 0:
            raise Exception('no more precomputed nonces')
        return self.cached.pop()

class Participant:
    def __init__(self, X, i, sk_i, nonce_cache):
        self.X = X
        self.i = i
        self.sk_i = sk_i
        self.nonce_cache = nonce_cache
        self.spre_i, self.pre_i = nonce_cache.get()

    def sign_round(self, msg, T, pre):
        s_i = sign_round(self.X, msg, T, pre, self.i, self.sk_i, self.spre_i)
        self.spre_i, self.pre_i = self.nonce_cache.get()
        return s_i, self.pre_i

def handle_requests(connection, nonce_cache):
    X, i, sk_i, is_malicious = recv_obj(connection)
    logging.debug(f'Received initialization data as participant {i}, is_malicious = {is_malicious}')

    participant = Participant(X, i, sk_i, nonce_cache)
    send_obj(connection, (i, None, participant.pre_i, 0))
    logging.debug(f'Sent initial pre_i value')

    while True:
        obj = recv_obj(connection)
        if obj is None:
            logging.debug('Connection closed')
            break

        msg, T, pre = obj

        logging.debug(f'Received sign_round request')
        if is_malicious:
            logging.debug('Malicious participant is ignoring request')
        else:
            start = time.time()
            s_i, pre_i = participant.sign_round(msg, T, pre)
            elapsed = time.time() - start
            send_obj(connection, (i, s_i, pre_i, elapsed))
            logging.info(f'Sent sign_round response and next pre_i value in {elapsed:.4f} seconds')

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) != 3:
        print(f'usage: {sys.argv[0]} <port> <num_precomputed_nonces>')
        sys.exit(1)

    nonce_cache = NonceCache()
    k = int(sys.argv[2])
    nonce_cache.precompute(k)
    logging.info(f'Done precomputing {k} nonces')

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
            handle_requests(connection, nonce_cache)
        except ConnectionResetError as e:
            print(e)
