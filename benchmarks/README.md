## Benchmark Results

- The coordinator was on a DigitalOcean virtual machine in San Francisco, of the lowest tier plan
- The participants were all running on a server in Germany
- There was a 158 ms ping between the two servers

```
rtt min/avg/max/mdev = 157.966/158.116/159.122/0.227 ms
```

The columns of the CSV files are defined as follows:

* `t`, `n`, and `f` are the parameters (threshold, total participants, malicious participants)
* `elapsed` is the total time needed to produce a signature, measured from the perspective the coordinator
	* It does NOT include the time needed to establish TCP connections with all participants
	* It DOES include the initial round trip to request and receive an initial nonce (with the exception of the benchmark results in `roast_3_5_preprocess.csv`, which excludes the time of this initial round trip)
* `ec_elapsed` is the time of all elliptic curve operations on the coordinator (e.g. verifying partial signatures)
* `send_cnt` and `recv_cnt` count the total number of network messages sent and received, respectively

Each configuration was run ten times to account for variability from random selection of malicious participants as well as nondeterminism in ordering of network messages.

* `roast_3_5.csv`, `roast_11_15.csv`, and `roast_67_100.csv` show how performance scales with the number of malicious participants, for fixed values of `t` and `n`
* `roast_majority.csv` shows how performance scales with the number of participants
* `roast_3_5_preprocess.csv` shows the potential gain from a "preprocessing" step, i.e. collecting nonces before the message is known, by starting the timer immediately before the first session (as opposed to immediately before requesting initial nonces)
	* However, the `send_cnt` and `recv_cnt` still account for messages exchanged during the preprocessing step
