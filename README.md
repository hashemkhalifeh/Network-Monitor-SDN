# Network-Monitor-SDN
# Introduction
This project consists of a Software Defined Network (SDN) of 3 hosts connected using 5 switches. The objective is to generate, monitor and measure real time SDN traffic and manage traffic flows in real time based on traffic measurement. The goal is to manage flows in real time such that all links in the network are as evenly loaded as possible based on traffic measurements. 

# Details
The experiment is executed using mininet installed on a Ubuntu VM on VirtualBox. Mininet creates a scalable SDN using OpenFlow on a single PC. Our network topology consisted of 3 hosts connected using 5 switches and a RYU controller to manage traffic. The topology is shown in the image below. 

<img src=/Images/Topology.png width="500">

# Part I
First, we use controller1.py to run the experiment such that the first packet of every new flow is sent to the controller and the controller installs new flows according to the following path rules:
* H1 --> H2: S3-S1-S4
* H1 --> H3: S3-S1-S5
* H2 --> H3: S4-S1-S5
We ran traffic for 10 min using the runTraffic command built into topology.py and collected port statistics to observe traffic rate across the different links. This method leaves certain links over utilized and other linke under utilized. In the next part we implemented a controller where traffic is balanced across available links and evenly as possible.

# Part II

