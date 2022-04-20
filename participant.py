from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

import logging
import sys

from roast import SessionContext, pre_round, sign_round
from transport import send_obj, recv_obj

class Participant:
    def __init__(self, i, sk_i):
        self.i = i
        self.sk_i = sk_i
        self.spre_i, self.pre_i = pre_round()

    def sign_round(self, ctx):
        s_i = sign_round(ctx, self.i, self.sk_i, self.spre_i)
        self.spre_i, self.pre_i = pre_round()
        return s_i, self.pre_i

def handle_requests(connection):
    i, sk_i, is_malicious = recv_obj(connection)
    logging.info(f'Received initialization data as participant {i}, is_malicious = {is_malicious}')

    participant = Participant(i, sk_i)
    send_obj(connection, (i, None, participant.pre_i))
    logging.info(f'Sent initial pre_i value')

    while True:
        ctx = recv_obj(connection)
        if ctx is None:
            logging.info('Connection closed')
            break

        logging.info(f'Received sign_round request')
        if is_malicious:
            logging.info('Malicious participant is ignoring request')
        else:
            s_i, pre_i = participant.sign_round(ctx)
            send_obj(connection, (i, s_i, pre_i))
            logging.info(f'Sent sign_round response and next pre_i value')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <port>')
        sys.exit(1)

    port = int(sys.argv[1])
    addr = ('0.0.0.0', port)

    sock = socket(AF_INET, SOCK_STREAM)
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, True)
    sock.bind(addr)
    sock.listen()

    while True:
        logging.info('Listening for incoming connections on', addr)

        connection, src = sock.accept()
        logging.info('Accepted connection from', src)

        try:
            handle_requests(connection)
        except ConnectionResetError as e:
            print(e)
