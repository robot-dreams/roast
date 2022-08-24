## Overview

This repository is a basic implementation of the ROAST protocol for robust threshold signatures, which is a variant of FROST. It's meant to be used only for measuring how performance scales with the various parameters of the protocol (e.g. threshold value, total number of participants, number of malicious participants).

**WARNING**: This implementation should NOT be used in production. Among other reasons, it relies on a completely trusted coordinator to generate and distribute private keys to participants.

We currently use the [`fastecdsa` library](https://github.com/AntonKueltz/fastecdsa) for elliptic curve operations, but a fully optimized implementation should use the [`secp256k1` library](https://github.com/bitcoin-core/secp256k1) instead.

## Running

The following example shows:

* `start_port = 12001`
* `threshold = 3`
* `total = 5`
* `malicious = 2`

1. First launch all the participants:

```shell
% for i in `seq 12001 12005`; do python3 participant.py $i 64 & done
```

The `num_precomputed_nonces` value of `64` indicates how many nonces to precompute before listening for connections.

2. Next, run the coordinator:

```shell
% python3 coordinator.py localhost 12001 3 5 2
```

Replace `localhost` with the correct host if you're not running the participants on the same machine as the coordinator. Note that it's possible to run the coordinator multiple times without relaunching all the participants, as long as the participants haven't run out of precomputed nonces.

## Protocol

1. Initialization

* For each of the `n` participants:
	* Coordinator sends `(X, i, x_i, is_malicious)` to initialize the participant
	* Participant responds with `(i, None, pre_i, 0)` to prepare the first round

2. Signing

* For each of the `t` ready participants in the current session:
	* Coordinator sends `(msg, T, pre)` to ask for a signature
	* Participant responds with `(i, s_i, pre_i, elapsed)` to sign and prepare for the next round
		* The `elapsed` value indicates how long it took the participant to produce the response
		* If the participant was initialized with `is_malicious = True`, it will fail to respond

## Implementation

Note that on the coordinator side, we use a `SessionContext` as a wrapper to hold various fields used during the protocol, in order to reduce the number of function parameters. A `SessionContext` consists of:

* `X`: public key
* `i_to_X`: map from participants `i` to public key shares `x_i`
* `msg`: message to be signed
* `T`: set of `t` participants for current session
* `R`: precomputed value of aggregate nonce (an optimization for the coordinator)
* `pre`: aggregate nonce
* `pre_i`: public nonce for the current participant
