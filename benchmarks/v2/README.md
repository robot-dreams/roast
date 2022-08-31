## Benchmark Results

- The coordinator was on a DigitalOcean instance in the San Francisco datacenter region
- All participants were running on a single DigitalOcean instance in Frankfurt datacenter region
	- Note that because there's no interaction between participants (only between the coordinator and each participant), we believe this scenario provides realistic timing results
- There was a 153 ms ping between the two servers

```
rtt min/avg/max/mdev = 152.794/152.985/154.218/0.339 ms
```

- The filename scheme is `roast_{t}_{n}.csv`, where t is the threshold value and n is the total number of participants
- The columns of the CSV files are defined as follows:
	- `t`, `n`, and `f` are the parameters (threshold, total participants, malicious participants)
	- `attacker_level` indicates the kind of attacker:
		- `STATIC` corresponds to a fixed set of attackers that always behave maliciously
		- `STATIC_COORDINATION` corresponds to a fixed set of attackers that coordinate to ensure that if multiple attackers are chosen in a single session, only one of them will behave maliciously
		- `ADAPTIVE` is to designed to simulate the worst-case scenario, in which the first `f` sessions all contain exactly one attacker who behaves maliciously
	- `elapsed` is the total time needed to produce a signature, measured from the perspective the coordinator
		- It does NOT include the time needed to establish TCP connections with all participants
		- It DOES include the initial round trip to request and receive an initial nonce
	- `send_cnt` and `recv_cnt` count the total number of network messages sent and received, respectively
	- `success_session_id` is the ID of the session for which the signing attempt succeeded
		- Since session IDs are incremented monotonically, this corresponds to the number of sessions needed (however, subsequent sessions might also have been started)
- Each configuration was run ten times to account for variability
