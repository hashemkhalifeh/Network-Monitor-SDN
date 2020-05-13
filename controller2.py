""" RYU Controller Code.
Manage new flows to follow prescribed path and measure traffic every 5sec 
(in bps) of each link for 10 mins and draw a figure of ( time vs. traffic rate ) for each link """

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import inet
from ryu.ofproto import ether
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from operator import attrgetter
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.lib import hub
import sys
from time import gmtime, mktime
from ryu.app import simple_switch_13


sys.stdout = open("output.txt", "w")

class ExampleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.port_features = {}
        self.arp_table = {}
        self.datapaths = {}
        self.port_speed = {}
        self.port_stats = {}
        self.stats = {}
        self.monitor_thread = hub.spawn(self._monitor)
        # Add ARP table entries for all hosts
        self.arp_table["10.0.0.1"] = "00:00:00:00:00:01"
        self.arp_table["10.0.0.2"] = "00:00:00:00:00:02"
        self.arp_table["10.0.0.2"] = "00:00:00:00:00:03"

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])

    def _state_change_handler(self, ev):

      """ Record datapath information """

      datapath = ev.datapath
      if ev.state == MAIN_DISPATCHER:
          if datapath.id not in self.datapaths:
              self.logger.debug('register datapath: %016x', datapath.id)
              self.datapaths[datapath.id] = datapath
      elif ev.state == DEAD_DISPATCHER:
          if datapath.id in self.datapaths:
              self.logger.debug('unregister datapath: %016x', datapath.id)
              del self.datapaths[datapath.id]

    def _monitor(self):

      """ Issue request for stats every 10 seconds """

      while True:
          self.stats['port'] = {}
          for dp in self.datapaths.values():
            self.port_features.setdefault(dp.id, {})
            self._request_stats(dp)
          hub.sleep(10)

    def _request_stats(self, datapath):

      """ Periodically request flow & port stats by issuing OFPFlowStatsRequest and OFPPortStatsRequest to switches """

      self.logger.debug('send stats request: %016x', datapath.id)
      ofproto = datapath.ofproto
      parser = datapath.ofproto_parser

      req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
      datapath.send_msg(req)



    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):

      """ Handler to reply to port statistics request """
      bodys = self.stats
      body = ev.msg.body
      msg = ev.msg
      dpid = ev.msg.datapath.id
#      self.stats['port'][dpid] = body
      for stat in sorted(body, key=attrgetter('port_no')):
        port_no = stat.port_no
        if port_no != ofproto_v1_3.OFPP_LOCAL:
          key = (dpid, port_no)
          value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
               stat.duration_sec, stat.duration_nsec)
          self._save_stats(self.port_stats, key, value, 5)

          # Get port speed and Save it.
          pre = 0
          period = 10
          tmp = self.port_stats[key]
          if len(tmp) > 1:
            # Calculate only the tx_bytes, not the rx_bytes
            pre = tmp[-2][0]
            period = self._get_period(tmp[-1][3], tmp[-1][4], tmp[-2][3], tmp[-2][4])
          speed = (self._get_speed(self.port_stats[key][-1][0], pre, period) * 8.0 )
          self._save_stats(self.port_speed, key, speed, 5)

          self.logger.info('datapath             port   ''rx-pkts  rx-bytes rx-error '
                'tx-pkts  tx-bytes tx-error  port-speed(B/s)')
          self.logger.info('----------------   -------- ''-------- -------- -------- '
                '-------- -------- -------- '
                '---------------- ')
          format = '%016x %8x %8d %8d %8d %8d %8d %8d %8.1f'

#          for stat in sorted(body, key=attrgetter('port_no')):
          self.logger.info(format, 
                     dpid, stat.port_no,
                     stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                     stat.tx_packets, stat.tx_bytes, stat.tx_errors,
                     speed)
          """ Conditional statement to route new traffic to alternate path for traffic from H1 to H2.
          traffic rate is measured and when the rate  for link S3 to S1 is half the available BW for that link new flows
          for H1 to H2 are sent through link between S3 and S2 to evenly load links """

          if speed > 750000 and ev.msg.datapath.id == 3 and stat.port_no == 2:
             self._modify_flows(ev.msg.datapath.id, stat.port_no)


#          for stat in sorted(body, key=attrgetter('port_no')):
          print (mktime(gmtime()),',',ev.msg.datapath.id,',',stat.port_no,',' ,speed)


    def _modify_flows(self, datapath, port):

          # Switch 3 rules
          self.add_layer4_rules_new(self.dp3, inet.IPPROTO_UDP, '10.0.0.3', 12, 3)

          # Switch 2 Rules
          self.add_layer4_rules_new(self.dp2, inet.IPPROTO_UDP, '10.0.0.3', 12, 3)


    def _save_stats(self, _dict, key, value, length=5):
      if key not in _dict:
        _dict[key] = []
      _dict[key].append(value)
      if len(_dict[key]) > length:
        _dict[key].pop(0)

    def _get_speed(self, now, pre, period):
      if period:
        return (now - pre) / (period)
      else:
        return 0

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
      return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)    

    def _get_time(self, sec, nsec):
      return sec + nsec / 1000000000.0

    def add_layer4_rules_new(self, datapath, ip_proto, ipv4_dst = None, priority = 4, fwd_port = None):
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(fwd_port)]
        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                ip_proto = ip_proto,
                                ipv4_dst = ipv4_dst)
        self.add_flow_new(datapath, priority, match, actions) 

    # Method to add flow entries
    def add_flow_new(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


        # Assigning rules for switches
        dpid = datapath.id  # Get datapath id to identify switches

        # Switch 1
        if dpid == 1:
          self.dp1 = datapath

        # Switch 2
        if dpid == 2:
          self.dp2 = datapath

        # Switch 3
        if dpid == 3:
          self.dp3 = datapath

          # Forward new UDP packet H1-H2 to the controller
          match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                  ipv4_src = '10.0.0.1',
                                  ipv4_dst = '10.0.0.2',
                                  ip_proto = inet.IPPROTO_UDP)

          actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]

          self.add_flow(datapath, 1, match, actions)

          # Forward new UDP packet H1-H3 to the controller
          match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                  ipv4_src = '10.0.0.1',
                                  ipv4_dst = '10.0.0.3',
                                  ip_proto = inet.IPPROTO_UDP)

          actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]

          self.add_flow(datapath, 1, match, actions)

        # Switch 4
        if dpid == 4:
          self.dp4 = datapath

          # Forward new UDP packet H1-H2 to the controller
          match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                  ipv4_src = '10.0.0.2',
                                  ipv4_dst = '10.0.0.3',
                                  ip_proto = inet.IPPROTO_UDP)

          actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]

          self.add_flow(datapath, 1, match, actions)

          # Forward new UDP packet H1-H3 to the controller
          match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                  ipv4_src = '10.0.0.2',
                                  ipv4_dst = '10.0.0.1',
                                  ip_proto = inet.IPPROTO_UDP)

          actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]

          self.add_flow(datapath, 1, match, actions)

        # Switch 5
        if dpid == 5:
          self.dp5 = datapath

          # Forward new UDP packet H1-H2 to the controller
          match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                  ipv4_src = '10.0.0.3',
                                  ipv4_dst = '10.0.0.2',
                                  ip_proto = inet.IPPROTO_UDP)

          actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]

          self.add_flow(datapath, 1, match, actions)

          # Forward new UDP packet H1-H3 to the controller
          match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                  ipv4_src = '10.0.0.3',
                                  ipv4_dst = '10.0.0.1',
                                  ip_proto = inet.IPPROTO_UDP)

          actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]

          self.add_flow(datapath, 1, match, actions)

    # Method to add path rules
    def add_layer4_rules(self, datapath, ip_proto, ipv4_dst = None, priority = 3, fwd_port = None):
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(fwd_port)]
        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                ip_proto = ip_proto,
                                ipv4_dst = ipv4_dst)
        self.add_flow(datapath, priority, match, actions) 

    # Method to add flow entries
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    """ Packet In Handler. Call back method when packet in message is sent from the switch to the controller"""
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        dst = pkt_ethernet.dst
        src = pkt_ethernet.src

        # get the received port number from packet_in message.
        port = msg.match['in_port']


        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._handle_arp(datapath, port, pkt_ethernet, pkt_arp)
            return
        pkt_udp = pkt.get_protocol(udp.udp)
        if pkt_udp:
            self._handle_udp(datapath, port, pkt)
            return 

    # Method to handle ARP messages
    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Get MAC address from ARP table
        arp_get_mac = self.arp_table[pkt_arp.dst_ip]

        # Generate ARP reply message
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=arp_get_mac))

        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=arp_get_mac,
                                 src_ip=pkt_arp.dst_ip,
                                 dst_mac=pkt_arp.src_mac,
                                 dst_ip=pkt_arp.src_ip))

        self._send_packet(datapath, port, pkt)

    # Method to handle UDP messages 
    def _handle_udp(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        pkt_udp = pkt.get_protocol(udp.udp)      
        udp_dst = pkt_udp.dst_port
        udp_src = pkt_udp.src_port

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        dst_ip = pkt_ipv4.dst
        src_ip = pkt_ipv4.src

        if src_ip == '10.0.0.1' and dst_ip == '10.0.0.2' :

          # Switch 3 rules
          self.add_layer4_rules(self.dp3, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
          self.add_layer4_rules(self.dp3, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)

          # Switch 1 rules
          self.add_layer4_rules(self.dp1, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
          self.add_layer4_rules(self.dp1, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)

          # Switch 4 rules
          self.add_layer4_rules(self.dp4, inet.IPPROTO_UDP, '10.0.0.2', 10, 1)
          self.add_layer4_rules(self.dp4, inet.IPPROTO_UDP, '10.0.0.1', 10, 2)

          #self._send_packet(self.dp4, port, pkt)

        if src_ip == '10.0.0.1' and dst_ip == '10.0.0.3' :

          # Switch 3 rules
          self.add_layer4_rules(self.dp3, inet.IPPROTO_UDP, '10.0.0.3', 10, 2)
          self.add_layer4_rules(self.dp3, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)

          # Switch 1 rules
          self.add_layer4_rules(self.dp1, inet.IPPROTO_UDP, '10.0.0.3', 10, 3)
          self.add_layer4_rules(self.dp1, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)

          # Switch 5 rules
          self.add_layer4_rules(self.dp5, inet.IPPROTO_UDP, '10.0.0.3', 10, 1)
          self.add_layer4_rules(self.dp5, inet.IPPROTO_UDP, '10.0.0.1', 10, 2)

          self._send_packet(self.dp5, port, pkt)

        if src_ip == '10.0.0.2' and dst_ip == '10.0.0.3':

          # Switch 4 rules
          self.add_layer4_rules(self.dp4, inet.IPPROTO_UDP, '10.0.0.3', 10, 2)
          self.add_layer4_rules(self.dp4, inet.IPPROTO_UDP, '10.0.0.2', 10, 1)

          # Switch 1 rules
          self.add_layer4_rules(self.dp1, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
          self.add_layer4_rules(self.dp1, inet.IPPROTO_UDP, '10.0.0.3', 10, 3)

          # Switch 5 rules
          self.add_layer4_rules(self.dp5, inet.IPPROTO_UDP, '10.0.0.3', 10, 1)
          self.add_layer4_rules(self.dp5, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)

          #self._send_packet(self.dp5, port, pkt)

    # Send Packet Out
    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

