Assignment 3:

This program analyzes a traceroute pcap file and returns information about the system of routers that create the route.

Usage:

python3 ./P3_Fall2024.py (pcap filename)

Output:

  
  Row   Components                                                   Details
  ==========================================================================================
  1     The IP address of the source node (R1)                       192.168.100.17
  ------------------------------------------------------------------------------------------
  2     The IP address of ultimate destination node (R1)             8.8.8.8
  ------------------------------------------------------------------------------------------
  3     The IP addresses of the intermediate destination nodes (R1)  142.104.68.167, 192.168.9.5, 142.104.68.1, 192.168.10.1, 192.168.8.6, 142.104.252.37, 142.104.252.246, 207.23.244.242, 199.212.24.64, 206.12.3.17, 206.81.80.17, 74.125.37.91, 72.14.237.123, 209.85.250.121, 209.85.249.155, 209.85.249.153
  ------------------------------------------------------------------------------------------
  4     The correct order of the intermediate destination nodes (R1) 142.104.68.167, 192.168.9.5, 142.104.68.1, 192.168.10.1, 192.168.8.6, 142.104.252.37, 142.104.252.246, 207.23.244.242, 199.212.24.64, 206.12.3.17, 206.81.80.17, 74.125.37.91, 72.14.237.123, 209.85.250.121, 209.85.249.155, 209.85.249.153
  ------------------------------------------------------------------------------------------
  5     The values in the protocol field of IP headers (R1)          1: ICMP, 17: UDP, 6: Unknown
  ------------------------------------------------------------------------------------------
  6     The number of fragments created from the original datagram (R1) 156
  ------------------------------------------------------------------------------------------
  7     The offset of the last fragment (R1)                         0
  ------------------------------------------------------------------------------------------
  8     The avg RTT to ultimate destination node (R1)                1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 142.104.68.167        1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 192.168.9.5           1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 142.104.68.1          1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 192.168.10.1          1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 192.168.8.6           1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 142.104.252.37        1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 142.104.252.246       1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 207.23.244.242        1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 199.212.24.64         1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 206.12.3.17           1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 206.81.80.17          1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 74.125.37.91          1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 72.14.237.123         1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 209.85.250.121        1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 8.8.8.8               1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 209.85.249.155        1055916032.00 ms
  8     The avg RTT between 192.168.100.17 and 209.85.249.153        1055916032.00 ms
  ------------------------------------------------------------------------------------------
  9     The std deviation of RTT to ultimate destination node (R1)   0.00 ms
  8     The avg std between 192.168.100.17 and 142.104.68.167        0.00 ms
  8     The avg std between 192.168.100.17 and 192.168.9.5           0.00 ms
  8     The avg std between 192.168.100.17 and 142.104.68.1          0.00 ms
  8     The avg std between 192.168.100.17 and 192.168.10.1          0.00 ms
  8     The avg std between 192.168.100.17 and 192.168.8.6           0.00 ms
  8     The avg std between 192.168.100.17 and 142.104.252.37        0.00 ms
  8     The avg std between 192.168.100.17 and 142.104.252.246       0.00 ms
  8     The avg std between 192.168.100.17 and 207.23.244.242        0.00 ms
  8     The avg std between 192.168.100.17 and 199.212.24.64         0.00 ms
  8     The avg std between 192.168.100.17 and 206.12.3.17           0.00 ms
  8     The avg std between 192.168.100.17 and 206.81.80.17          0.00 ms
  8     The avg std between 192.168.100.17 and 74.125.37.91          0.00 ms
  8     The avg std between 192.168.100.17 and 72.14.237.123         0.00 ms
  8     The avg std between 192.168.100.17 and 209.85.250.121        0.00 ms
  8     The avg std between 192.168.100.17 and 8.8.8.8               0.00 ms
  8     The avg std between 192.168.100.17 and 209.85.249.155        0.00 ms
  8     The avg std between 192.168.100.17 and 209.85.249.153        0.00 ms
  ------------------------------------------------------------------------------------------
  10    The number of probes per TTL (R2)                            TTL 64: 20, TTL 53: 19, TTL 1: 3, TTL 2: 3, TTL 3: 3, TTL 4: 3, TTL 5: 3, TTL 6: 3, TTL 7: 3, TTL 8: 3, TTL 9: 3, TTL 10: 3, TTL 11: 3, TTL 12: 3, TTL 13: 3, TTL 14: 3, TTL 15: 3, TTL 16: 3, TTL 17: 3, TTL 18: 1, TTL 40: 1
  ------------------------------------------------------------------------------------------
  11    Right answer to the second question (R2)                     Yes
  ------------------------------------------------------------------------------------------
  12    Right answer to the third/or fourth question (R2)            Table attached
  ==========================================================================================
