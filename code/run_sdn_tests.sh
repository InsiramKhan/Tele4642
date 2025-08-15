#!/bin/bash

echo "⚙️  Running SDN test suite between h_0_0_2 and h_0_0_3..."

mnexec -a $(pgrep -f "h_0_0_2") bash <<EOF
echo "🟢 Test 1: ICMP ping"
h_0_0_3 iperf3 -s&
h_0_0_2 ping -c 3 10.0.0.3
sleep 1

echo "🟢 Test 2: TCP iperf3 (benign)"
h_0_0_3 iperf3 -s&
h_0_0_2 iperf3 -c 10.0.0.3
sleep 1


echo "🟢 Test 3: UDP iperf3 (should be malicious if pkt_len > 1200)"
h_0_0_3 iperf3 -s&
h_0_0_2 iperf3 -c 10.0.0.3 -u -b 1M
sleep 1

echo "🔴 Test 4: TCP SYN flood using hping3"
h_0_0_3 iperf3 -s&
h_0_0_2 hping3 --flood -S -p 12345 10.0.0.3 exit

sleep 3
killall hping3
sleep 1

echo "🔴 Test 5: UDP flood using hping3"
h_0_0_3 iperf3 -s&
h_0_0_2 hping3 --flood -2 -p 53 10.0.0.3 
sleep 3
killall hping3
sleep 1

echo "🟡 Test 6: TCP to unknown high port"
h_0_0_3 iperf3 -s&
h_0_0_2 hping3 -S -p 9999 10.0.0.3 -c 5
sleep 1

echo "✅ All tests completed."
EOF
