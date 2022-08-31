from multiprocessing import Queue

import logging
import secrets
import sys

from coordinator import AttackerLevel, AttackerStrategy, Coordinator
from model import CoordinatorModel
from shamir import split_secret

import fastec

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) != 6:
        print(f'usage: {sys.argv[0]} <host> <start_port> <t> <n> <runs_per_config>')
        sys.exit(1)

    host = sys.argv[1]
    start_port = int(sys.argv[2])
    t = int(sys.argv[3])
    n = int(sys.argv[4])
    runs_per_config = int(sys.argv[5])

    msg = b""
    i_to_addr = {i + 1: (host, start_port + i) for i in range(n)}
    i_to_cached_ctx = {i + 1: Queue() for i in range(n)}
    print(i_to_addr)

    actions = Queue()
    outgoing = Queue()
    coordinator = Coordinator(actions, outgoing, i_to_cached_ctx)
    coordinator.setup(i_to_addr)
    print(f'Finished establishing connections to {n} participants')

    # This is insecure; in practice we'd use DKG, but since
    # key generation is not the focus of the ROAST protocol, we will
    # keep the implementation simple by having the coordinator
    # act as a centralized dealer.
    sk = 1 + secrets.randbelow(fastec.n - 1)
    i_to_sk = split_secret(sk, t, n)

    X = sk * fastec.G
    i_to_X = {i: sk_i * fastec.G for i, sk_i in i_to_sk.items()}
    print(f'Finished keygen for t = {t}, n = {n}')

    with open(f'roast_{t}_{n}.csv', 'w') as outfile:
        print("t,n,f,attacker_level,elapsed,send_cnt,recv_cnt,success_session_id", file=outfile)
        for f in range(n - t + 1):
            for attacker_level in AttackerLevel:
                for i in range(runs_per_config):
                    model = CoordinatorModel(X, i_to_X, t, n, msg)
                    attacker_strategy = AttackerStrategy(attacker_level, n, f)
                    elapsed, send_count, recv_count, sid = coordinator.run(i_to_sk, model, attacker_strategy)
                    print(t, n, f, attacker_level, elapsed, send_count, recv_count, sid, sep=',', file=outfile)
                    print(f'Finished run {i + 1} of {runs_per_config} for config: (t = {t}, n = {n}, f = {f}, attacker_level = {attacker_level})')
