from dataclasses import dataclass, field
from queue import PriorityQueue, Queue
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from threading import Thread
from typing import Any

import secrets
import time

from shamir import split_secret
from model import ActionType, CoordinatorModel
from roast import verify
from transport import send_obj, recv_obj

import fastec

@dataclass(order=True)
class PriorityAction:
    priority: int
    action: Any=field(compare=False)

class Coordinator:
    def __init__(self, model, actions, outgoing):
        self.model = model
        self.actions = actions
        self.outgoing = outgoing
        self.connections = {}

    def queue_action(self, action_type, data):
        self.actions.put(PriorityAction(action_type.value, (action_type, data)))

    def queue_incoming(self, sock):
        while True:
            data = recv_obj(sock)
            if not data:
                break
            self.queue_action(ActionType.INCOMING, data)

    def send_outgoing(self):
        while True:
            i, data = self.outgoing.get()
            assert i in self.connections
            send_obj(self.connections[i], data)

    def launch(self, i_to_addr, i_to_sk):
        for i, addr in i_to_addr.items():
            self.connections[i] = socket(AF_INET, SOCK_STREAM)
            self.connections[i].setsockopt(SOL_SOCKET, SO_REUSEADDR, True)
            self.connections[i].connect(addr)
            print(f'Established connection to participant {i} at {addr}')
            send_obj(self.connections[i], (i, i_to_sk[i]))
            Thread(target=self.queue_incoming, args=[self.connections[i]], daemon=True).start()

        Thread(target=self.send_outgoing, daemon=True).start()

        start = time.time()
        while True:
            action_type, data = self.actions.get().action

            if action_type == ActionType.NO_OP:
                pass

            elif action_type == ActionType.INCOMING:
                i, s_i, pre_i = data
                if s_i is None:
                    print(f'Initial incoming message from participant {i}')
                else:
                    print(f'Incoming message from participant {i} in session {self.model.i_to_sid[i]}')
                action_type, data = self.model.handle_incoming(i, s_i, pre_i)
                self.queue_action(action_type, data)

            elif action_type == ActionType.SESSION_START:
                print(f'Enough participants are ready, starting new session with sid {self.model.sid_ctr}')
                for item in data:
                    ctx, T, i = item
                    self.outgoing.put((i, (ctx, T)))

            elif action_type == ActionType.SESSION_SUCCESS:
                ctx, sig = data
                assert verify(ctx, sig)
                end = time.time()
                print(f'Successful protocol run in {end - start:.4f} seconds')
                break

            else:
                raise Exception('Unknown ActionType', action_type)

if __name__ == '__main__':
    t = 2
    n = 3
    msg = secrets.token_bytes(32)

    i_to_addr = {
        1: ("localhost", 12001),
        2: ("localhost", 12002),
        3: ("localhost", 12003),
    }

    # This is insecure; in practice we'd use DKG, but since
    # key generation is not the focus of the RoAST protocol, we will
    # keep the implementation simple by having the coordinator
    # act as a centralized dealer.
    sk = 1 + secrets.randbelow(fastec.n - 1)
    i_to_sk = split_secret(sk, t, n)

    X = sk * fastec.G
    i_to_X = {i: sk_i * fastec.G for i, sk_i in i_to_sk.items()}

    model = CoordinatorModel(X, i_to_X, t, n, msg)
    actions = PriorityQueue()
    outgoing = Queue()

    coordinator = Coordinator(model, actions, outgoing)
    coordinator.launch(i_to_addr, i_to_sk)
