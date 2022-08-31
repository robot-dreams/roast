## Overview

This repository contains a naive implementation of the [ROAST protocol](https://eprint.iacr.org/2022/550) for robust threshold signatures. ROAST is intended as a wrapper on top of threshold signature schemes such as [FROST](https://eprint.iacr.org/2020/852).

The implementation here is intended only as a proof of concept, and for measuring how performance scales with various protocol parameters (e.g. threshold value, total number of participants, number and strategy of malicious participants).

**WARNING**: This implementation should NOT be used in production. Among other reasons, it relies on a trusted coordinator to generate and distribute private keys to participants, which defeats the purpose of using a threshold signature scheme in the first place.

We currently use the [`fastecdsa` library](https://github.com/AntonKueltz/fastecdsa) for elliptic curve operations, but a more optimized implementation should use the [`secp256k1` library](https://github.com/bitcoin-core/secp256k1) instead.

## Running

The following example shows:

* `start_port = 12001`
* `threshold = 3`
* `total = 5`
* `malicious = 2`
* `attacker_level = 0` (higher values give more sophisticated strategies)
* `runs = 10` (there will be 10 separate runs, and each run will include 1 or more sessions)

1. First launch all the participants:

```shell
% for i in `seq 12001 12005`; do python3 participant.py $i & done
```

2. Next, run the coordinator:

```shell
% python3 coordinator.py localhost 12001 3 5 2 0 10
```

Replace `localhost` with the correct host if you're not running the participants on the same machine as the coordinator. Use `bench_all.py` instead of `coordinator.py` if you'd like to run through all possible attacker strategies for given values of `t`, `n`.

## Protocol

1. Initialization

* For each of the `n` participants:
	* Coordinator sends `(X, i, x_i)` to initialize the participant
	* Participant responds with `(i, None, pre_i)` to prepare the first round

2. Signing

* For each of the `t` ready participants in the current session:
	* Coordinator sends `(msg, T, pre, is_malicious)` to ask for a signature
		* We use the `is_malicious` parameter so that we can use the centralized coordinator to simulate a sophisticated attacker strategy
	* Participant responds with `(i, s_i, pre_i)` to sign and prepare for the next round
		* However, a participant that received `is_malicious = True` will instead ignore the coordinator's message and fail to respond, in an attempt to stall the protocol

## Implementation Notes

On the coordinator side, we use a `SessionContext` to combine various fields used during the protocol, in order to reduce the number of function parameters passed around. A `SessionContext` consists of:

* `X`: public key
* `i_to_X`: map from participants `i` to public key shares `x_i`
* `msg`: message to be signed
* `T`: set of `t` participants for current session
* `R`: precomputed value of aggregate nonce (an optimization for the coordinator)
* `pre`: aggregate nonce
* `pre_i`: public nonce for the current participant
