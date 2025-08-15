# SDN-Based Adaptive Firewall & Traffic Monitor (MUD + ML/Trust)


Live site: https://insiramkhan.github.io/Tele4642/index.html

Course: TELE4642 – Network Performance (UNSW)

Author: Insiramuddin Khan (z5345138)


This project demonstrates an SDN controller (Ryu) that enforces MUD allowlists and augments them with an ML/Trust layer (binary classifier + PageRank-style trust). The public site presents a static screenshot report of the lab demo so reviewers don’t need to run the stack.



# What’s inside

Results & Evaluation — Screenshot Report (static HTML)
Evidence for: (1) MUD baseline enforcement, (2) ML/Trust interventions, (3) traffic/trust characteristics over time.
Test Cases: Benign baseline, UDP flood, TCP SYN flood, controller log capture.
Controller Evidence: Ryu logs and blocked/quarantined flows.
Analytics: Trust (PageRank), confusion matrix, ROC.



# How the demo was run (summary)

This section is for reproducibility; the public site uses screenshots only.

Prereqs (tested): Ubuntu 20.04/22.04, Python 3.9+, Mininet, Ryu, iperf3.

# Mininet (example)
sudo python3 project_tree.py

# Ryu controller
ryu-manager project_ryu.py ryu.app.ofctl_rest

# Traffic examples (from Mininet CLI)

h_0_0_3 iperf3 -s &
h_0_0_2 iperf3 -c 10.0.0.3 -u -b 1M        # TCP stream

add flood/SYN tests per tests/test.sh

Artifacts (CSV/logs) were exported and then screen-captured to populate assets/results/.




# Interpreting the key plots

Confusion Matrix: verifies correct separation of benign vs malicious flows during tests (diagonal dominance).

ROC Curve: shows high TPR at low FPR across thresholds → robust detection, not just at a single cutoff.

Trust (PageRank): lower-trust devices correlate with more interventions, supporting prioritised scrutiny.

Ryu Logs / Blocked Flows: timestamped 5-tuples evidencing PacketIn → MUD → ML/Trust → decision → flow_mod.


# Notes on MUD + ML/Trust

MUD: device-specific allowlists provide baseline allow/deny.
ML/Trust layer: mitigates anomalies even when MUD would allow, using a classifier plus trust scores from a flow graph.

 
# License & Acknowledgements
License: Not yet
Acknowledgements: UNSW TELE4642 materials; Ryu SDN framework; Mininet.

# Contact

# Author: Insiramuddin Khan - insiramuddin.khan@student.unsw.edu.au

# Live site: https://insiramkhan.github.io/Tele4642/index.html
# Repo: https://github.com/InsiramKhan/Tele4642
