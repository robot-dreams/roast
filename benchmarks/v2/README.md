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

### Plotting

The `summarize.py` script summarizes the raw data into a format that can directly be read by a LaTeX `tikzpicture` plot. For example:

```latex
\begin{tikzpicture}
	\begin{axis}[
		legend style={
			at={(0.985,0.065)},
			anchor={south east},
			font=\small,
			inner sep=2pt,
		},
		legend cell align=left,
		xlabel=Fraction $f/(n - t)$ of malicious signers,
		ylabel={Average running time [s]},
		xmin=0,
		xmax=1,
		xtick={0, 0.25, ..., 1},
		xticklabels={0, 1/4, 1/2, 3/4, 1},
		ymin=0,
	]
	\addplot[color=blue,mark=x] table {benchmark/benchmark-adaptive-67-100.dat};
	\addplot[color=brown,mark=triangle] table {benchmark/benchmark-adaptive-34-50.dat};
	\addplot[color=red,mark=diamond] table {benchmark/benchmark-adaptive-11-15.dat};
	\addplot[color=green,mark=square] table {benchmark/benchmark-adaptive-3-5.dat};
	\addplot[color=black,dashed] {0.158};
	\legend{67-of-100$\!$,34-of-50,11-of-15,3-of-5,RTT}
	\end{axis}
\end{tikzpicture}
```
