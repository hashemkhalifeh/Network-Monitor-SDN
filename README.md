# Network-Monitor-SDN
# Introduction
This project consists of a Software Defined Network (SDN) of 3 hosts connected using 5 switches. The objective is to generate, monitor and measure real time SDN traffic and manage traffic flows in real time based on traffic measurement. The goal is to manage flows in real time such that all links in the network are as evenly loaded as possible based on traffic measurements. 

# Details
The experiment is executed using mininet installed on a Ubuntu VM on VirtualBox. Mininet creates a scalable SDN using OpenFlow on a single PC. Our network topology consisted of 3 hosts connected using 5 switches and a RYU controller to manage traffic. The topology is shown in the image below. 

<img src=/Images/Topo.png width="500">

# Part I
First, we use controller1.py to run the experiment such that the first packet of every new flow is sent to the controller and the controller installs new flows according to the following path rules:
* H1 --> H2: S3-S1-S4
* H1 --> H3: S3-S1-S5
* H2 --> H3: S4-S1-S5
We ran traffic for 10 min using the runTraffic command built into topology.py and collected port statistics to observe traffic rate across the different links. This method leaves certain links over utilized and other linke under utilized. In the next part we implemented a controller where traffic is balanced across available links and evenly as possible.

# Part II
In this part we implement controller2.py to balance traffic across available links as evenly as possible. The method can be illustrated in the following pseudo-code:

```
port_stats = [] #initiate an empty array for port statistics
monitor:
  request_stats for a datapath every 10 seconds
event of port stats reply triggered every 10 seconds 
  port_stats_reply:
    key = (dpid, port_num) to identify datapath and port number value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
    stat.duration_sec, stat.duration_nsec)
    use save_stats handler to store key and value in port_stats array
    get speed for switch port number using get_speed handler access port_stats to get tx_bytes_old
    get_speed = tx_bytes_new - tx_bytes_old / 10 
    
    if speed > 750000 (bps) and switch == 3 and port_no == 2: 
    modify_flows:
      redirect H1 to H3 traffic from S3-S1-S5 to S3-S2-S5 to balance traffic
      by installing new flow with higher priority
 ```
After we implemented this method of flow control we collected port statistics and observed that traffic we distributed as evenly as possible across availabe links.

# References
https://osrg.github.io/ryu-book/en/html/traffic_monitor.html 
https://github.com/muzixing/ryu/blob/master/ryu/app/simple_monitor.py
