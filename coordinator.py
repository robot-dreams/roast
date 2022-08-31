from dataclasses import dataclass, field
from multiprocessing import Process, Queue, Value
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, IPPROTO_TCP, TCP_NODELAY
from typing import Any
from enum import Enum

import logging
import secrets
import sys
import time

from shamir import split_secret
from model import ActionType, CoordinatorModel
from roast import share_val, verify
from transport import send_obj, recv_obj

import fastec

@dataclass(order=True)
class PriorityAction:
    priority: int
    action: Any=field(compare=False)

class AttackerLevel(Enum):
    # Set of malicious participants determined in the beginning
    STATIC = 0
    # Same as STATIC but at most one participant behaves maliciously in a session
    STATIC_COORDINATION = 1
    # Exactly one malicious participant in the first m sessions
    ADAPTIVE = 2

def random_sample(items, k):
    items = list(items)
    secrets.SystemRandom().shuffle(items)
    return items[:k]

class AttackerStrategy:
    def __init__(self, level, n, m):
        self.level = level
        self.n = n
        self.m = m
        self.static_attackers = random_sample(range(1, n + 1), m)

    def choose_malicious(self, T, sid_ctr):
        if self.level == AttackerLevel.STATIC:
            return self.static_attackers[:]
        elif self.level == AttackerLevel.STATIC_COORDINATION:
            candidates = set(T).intersection(self.static_attackers)
            return random_sample(candidates, 1)
        elif self.level == AttackerLevel.ADAPTIVE:
            return random_sample(T, sid_ctr <= self.m)
        else:
            raise ValueError('Unexpected AttackerLevel:', self.level)

class Coordinator:
    def __init__(self, actions, outgoing, i_to_cached_ctx):
        self.actions = actions
        self.outgoing = outgoing
        self.i_to_cached_ctx = i_to_cached_ctx
        self.connections = {}
        self.run_id = Value('i', 0)

    def queue_action(self, action_type, data):
        self.actions.put(PriorityAction(action_type.value, (action_type, data)))

    def queue_incoming_loop(self, sock, cached_ctx_queue):
        while True:
            obj = recv_obj(sock)
            if not obj:
                break
            run_id, (i, s_i, pre_i) = obj
            # Ignore incoming messages from wrong run_id
            with self.run_id.get_lock():
                if run_id != self.run_id.value:
                    logging.debug(f'Ignoring incoming message from previous run (message run_id = {run_id}, my run_id = {self.run_id.value})')
                    continue
            share_is_valid = False
            if s_i is not None:
                ctx_run_id, ctx = cached_ctx_queue.get()
                # Discard queue items from previous runs
                while ctx_run_id != run_id:
                    ctx_run_id, ctx = cached_ctx_queue.get()
                share_is_valid = share_val(ctx, i, s_i)
            data = i, s_i, pre_i, share_is_valid
            self.queue_action(ActionType.INCOMING, data)

    def send_outgoing_loop(self):
        while True:
            i, data = self.outgoing.get()
            assert i in self.connections
            with self.run_id.get_lock():
                send_obj(self.connections[i], (self.run_id.value, data))

    def setup(self, i_to_addr):
        for i, addr_i in i_to_addr.items():
            self.connections[i] = socket(AF_INET, SOCK_STREAM)
            self.connections[i].setsockopt(SOL_SOCKET, SO_REUSEADDR, True)
            self.connections[i].setsockopt(IPPROTO_TCP, TCP_NODELAY, True)
            self.connections[i].connect(addr_i)
            logging.debug(f'Established connection to participant {i} at {addr_i}')

        Process(target=self.send_outgoing_loop, daemon=True).start()
        for i in self.connections.keys():
            Process(target=self.queue_incoming_loop, args=[self.connections[i], self.i_to_cached_ctx[i]], daemon=True).start()

    def run(self, i_to_sk, model, attacker_strategy):
        with self.run_id.get_lock():
            self.run_id.value += 1

        send_count = 0
        recv_count = 0

        send_count += len(i_to_sk)
        for i, sk_i in i_to_sk.items():
            self.outgoing.put((i, (model.X, i, sk_i)))

        start = time.time()

        while True:
            action_type, data = self.actions.get().action

            if action_type == ActionType.NO_OP:
                pass

            elif action_type == ActionType.INCOMING:
                recv_count += 1

                i, s_i, pre_i, share_is_valid = data
                if s_i is None:
                    logging.debug(f'Initial incoming message from participant {i}')
                else:
                    logging.debug(f'Incoming message from participant {i} in session {model.i_to_sid[i]}')
                action_type, data = model.handle_incoming(i, s_i, pre_i, share_is_valid)
                self.queue_action(action_type, data)

            elif action_type == ActionType.SESSION_START:
                send_count += len(data)

                sid_ctr = model.sid_ctr
                logging.debug(f'Enough participants are ready, starting new session with sid {sid_ctr}')
                T = model.sid_to_T[sid_ctr]
                session_malicious = attacker_strategy.choose_malicious(T, sid_ctr)

                with self.run_id.get_lock():
                    run_id = self.run_id.value
                for item in data:
                    ctx, i = item
                    self.i_to_cached_ctx[i].put((run_id, ctx))
                    self.outgoing.put((i, (ctx.msg, ctx.T, ctx.pre, i in session_malicious)))

            elif action_type == ActionType.SESSION_SUCCESS:
                ctx, sig = data
                end = time.time()
                assert verify(ctx, sig)
                return end - start, send_count, recv_count

            else:
                raise Exception('Unknown ActionType', action_type)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) != 8:
        print(f'usage: {sys.argv[0]} <host> <start_port> <threshold> <total> <malicious> <attacker_level> <runs>')
        sys.exit(1)

    host = sys.argv[1]
    start_port = int(sys.argv[2])
    t = int(sys.argv[3])
    n = int(sys.argv[4])
    m = int(sys.argv[5])
    attacker_level = AttackerLevel(int(sys.argv[6]))
    runs = int(sys.argv[7])

    msg = b""
    i_to_addr = {i + 1: (host, start_port + i) for i in range(n)}

    # This is insecure; in practice we'd use DKG, but since
    # key generation is not the focus of the ROAST protocol, we will
    # keep the implementation simple by having the coordinator
    # act as a centralized dealer.
    sk = 1 + secrets.randbelow(fastec.n - 1)
    i_to_sk = split_secret(sk, t, n)

    X = sk * fastec.G
    i_to_X = {i: sk_i * fastec.G for i, sk_i in i_to_sk.items()}
    i_to_cached_ctx = {i + 1: Queue() for i in range(n)}

    actions = Queue()
    outgoing = Queue()
    coordinator = Coordinator(actions, outgoing, i_to_cached_ctx)
    coordinator.setup(i_to_addr)

    for _ in range(runs):
        model = CoordinatorModel(X, i_to_X, t, n, msg)
        attacker_strategy = AttackerStrategy(attacker_level, n, m)
        elapsed, send_count, recv_count = coordinator.run(i_to_sk, model, attacker_strategy)
        print(t, n, m, attacker_level, elapsed, send_count, recv_count, model.sid_ctr, sep=',')
