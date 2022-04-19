## Overview

This repository is a basic implementation of the RoAST protocol for robust threshold signatures, which is a variant of FROST. It's meant to be used only for measuring how performance scales with the various parameters of the protocol (e.g. threshold value, total number of participants, number of malicious participants).

**WARNING**: This implementation should NOT be used in production. Among other reasons, it relies on a completely trusted coordinator to generate and distribute private keys to participants.

We currently use the [`fastecdsa` library](https://github.com/AntonKueltz/fastecdsa) for elliptic curve operations, but a fully optimized implementation should use the [`secp256k1` library](https://github.com/bitcoin-core/secp256k1) instead.

## Protocol

1. Initialization

* For each of the `n` participants:
	* Coordinator sends `(i, x_i)` to initialize the participant
	* Participant responds with `(None, pre_i)` to prepare the first round

2. Signing

* For each of the `t` ready participants in the current session:
	* Coordinator sends `ctx` (a `SessionContext` object) to ask for a signature
	* Participant responds with `(i, s_i, pre_i)` to sign and prepare for the next round

A `SessionContext` object consists of the following fields:

* `X`: public key
* `i_to_X`: map from participants `i` to public key shares `x_i`
* `msg`: message to be signed
* `T`: set of `t` participants for current session
* `pre`: aggregate nonce
* `pre_i`: public nonce for the current participant
