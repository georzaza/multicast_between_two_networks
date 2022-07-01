'''
Zazanis Georgios, 1069, zazanis@uth.gr


TESTS THAT WERE WORKING WITH THIS CONTROLLER:

When all extra functionality in mininet-router-multicase.py was commented:

    sequence 1:
        h1 sysctl net.ipv4.icmp_echo_ignore_broadcasts=0 
        h1 smcrouted -I h1
        h1 smcroutectl -I h1 join h1-eth1 239.0.0.1
        h4 iperf -c 239.0.0.2 -u 

    sequence 2:
        h1 sysctl net.ipv4.icmp_echo_ignore_broadcasts=0 
        h1 smcrouted -I h1
        h1 smcroutectl -I h1 join h1-eth1 239.0.0.1
        h4 iperf -c 239.0.0.1 -u 

    sequence 3:
        h1 sysctl net.ipv4.icmp_echo_ignore_broadcasts=0 
        h2 sysctl net.ipv4.icmp_echo_ignore_broadcasts=0 
        h1 smcrouted -I h1
        h2 smcrouted -I h2
        h1 smcroutectl -I h1 join h1-eth1 239.0.0.1
        h2 smcroutectl -I h2 join h2-eth1 239.0.0.2
        h4 iperf -c 239.0.0.2 -u 
        h4 iperf -c 239.0.0.1 -u 
        h1 smcroutectl -I h1 leave h1-eth1 239.0.0.1
        h4 iperf -c 239.0.0.1 -u 
        h2 smcroutectl -I h2 leave h2-eth1 239.0.0.1
        h4 iperf -c 239.0.0.1 -u 
        h2 smcroutectl -I h2 leave h2-eth1 239.0.0.2
        h4 iperf -c 239.0.0.2 -u 
    
    Everything seemed to be working as intended while on any point of the above
    sequences of commands.

When all extra functionality in mininet-router-multicase.py was un-commented:
    Everything seemed to be working as intended.
    
'''
 


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import igmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types


ARP = ether_types.ETH_TYPE_ARP
IP = ether_types.ETH_TYPE_IP

S1A_LEFT_MAC = '00:00:00:00:01:01'
S1A_RIGHT_MAC = '00:00:00:00:03:01'
S1A_NET1_IP = '192.168.1.1'

S1B_LEFT_MAC = '00:00:00:00:03:02'
S1B_RIGHT_MAC = '00:00:00:00:02:01'
S1B_NET2_IP = '192.168.2.1'

NET1 = '192.168.1.0'
NET2 = '192.168.2.0'

MCAST_IP1 = '239.0.0.1'
MCAST_IP2 = '239.0.0.2'
MCAST_MAC1 = '01:00:5e:00:00:01'
MCAST_MAC2 = '01:00:5e:00:00:02'

MULTICAST_MAC_PREFIX = '01:00:5e'
PORT_TO_ROUTER = 1      # hardcoded for both switches.


class SimpleSwitch(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mult_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    # Since we are working with only 2 multicast IP addresses, we could do a
    # combination of 4 matches and 2 actions, combine those and get 4 flows
    # for each switch.
    # Instead of doing that, I added netmask 30 (matching all 239.0.0.0 to 239.0.0.3)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = msg.datapath_id
        if dpid == 0x1A:
            match1 = datapath.ofproto_parser.OFPMatch(nw_dst_mask=30, nw_dst=MCAST_IP1, in_port=1, dl_type=0x800)
            match2 = datapath.ofproto_parser.OFPMatch(nw_dst_mask=30, nw_dst=MCAST_IP1, in_port=2, dl_type=0x800)
            actions1 = [datapath.ofproto_parser.OFPActionSetDlSrc(S1A_LEFT_MAC),
                        datapath.ofproto_parser.OFPActionOutput(2)]
            actions2 = [datapath.ofproto_parser.OFPActionSetDlSrc(S1A_RIGHT_MAC),
                        datapath.ofproto_parser.OFPActionOutput(1)]
            self.add_flow(datapath, match1, actions1)
            self.add_flow(datapath, match2, actions2)
        elif dpid == 0x1B:
            match1 = datapath.ofproto_parser.OFPMatch(nw_dst_mask=30, nw_dst=MCAST_IP1, in_port=1, dl_type=0x800)
            match2 = datapath.ofproto_parser.OFPMatch(nw_dst_mask=30, nw_dst=MCAST_IP1, in_port=2, dl_type=0x800)
            actions1 = [datapath.ofproto_parser.OFPActionSetDlSrc(S1B_RIGHT_MAC),
                        datapath.ofproto_parser.OFPActionOutput(2)]
            actions2 = [datapath.ofproto_parser.OFPActionSetDlSrc(S1B_LEFT_MAC),
                        datapath.ofproto_parser.OFPActionOutput(1)]
            self.add_flow(datapath, match1, actions1)
            self.add_flow(datapath, match2, actions2)
    

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        self.mac_to_port.setdefault(dpid, {})
        self.mult_to_port.setdefault(dpid, {})

        # filter which packets to show to output.
        if ( str(hex(ethertype)) != '0x86dd'):
            self.logger.info('\npacket in %s %s %s %s in_port=%s', hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)


        if dpid == 0x2 or dpid == 0x3:
            # multicast packet
            if dst[:8] == MULTICAST_MAC_PREFIX:
                ip_packet = pkt.get_protocols(ipv4.ipv4)
                
                # igmp packet
                if ip_packet and ip_packet[0].proto==2:
                    igmp_packet = pkt.get_protocols(igmp.igmp)
                    multicast_ip = igmp_packet[0].records[0].address
                    
                    # igmp join packet
                    if (igmp_packet[0].records[0].type_ == 4):
                        if (self.learn_subscribers_ports(msg.in_port, multicast_ip, dpid)):
                            # At this point we have added a new port in the list 
                            # for this multicast. We need to delete the old flows
                            # so that we can add the new flow later. (this may also
                            # delete unwanted 'drop' flows from a previous igmp leave)
                            match = parser.OFPMatch(dl_dst=self.multicast_ip_to_mac(multicast_ip))
                            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]
                            remove_flow = parser.OFPFlowMod(datapath, match, 0,
                                          ofproto.OFPFC_DELETE,0, 0, 30000, 0xffffffff, 
                                          ofproto.OFPP_NONE, 0, actions)
                            datapath.send_msg(remove_flow)
                        print(self.mult_to_port[dpid])
                        
                    # igmp leave packet
                    elif (igmp_packet[0].records[0].type_ == 3):
                        if msg.in_port in self.mult_to_port[dpid][multicast_ip]:
                            self.mult_to_port[dpid][multicast_ip].remove(msg.in_port)
                            print("Switch " + hex(dpid) + ": Removed port "+str(msg.in_port)
                                                        + " for " + multicast_ip)
                            print(self.mult_to_port[dpid])
                            match = parser.OFPMatch(dl_dst=self.multicast_ip_to_mac(multicast_ip))
                            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]
                            remove_flow = parser.OFPFlowMod(datapath, match, 0,
                                          ofproto.OFPFC_DELETE,0, 0, 30000, 0xffffffff, 
                                          ofproto.OFPP_NONE, 0, actions)
                            datapath.send_msg(remove_flow)
                    return
                else:
                    # not an igmp packet but still a multicast packet.
                    udp_packet = pkt.get_protocols(udp.udp)
                    dst_ip = ip_packet[0].dst
                    data = msg.data
                    out_port = [PORT_TO_ROUTER]  # always send multicast traffic to router.
                    # Case when for this switch there are no subscribed hosts
                    # for this multicast group.
                    if dst_ip not in self.mult_to_port[dpid]:
                        self.mult_to_port[dpid][dst_ip] = out_port
                        match = parser.OFPMatch(in_port=msg.in_port, dl_dst=dst)
                        actions = [parser.OFPActionOutput(PORT_TO_ROUTER)]
                        out = parser.OFPPacketOut(datapath=datapath, 
                                    buffer_id=ofproto.OFP_NO_BUFFER, 
                                    in_port=ofproto.OFPP_CONTROLLER,
                                    actions=actions, data=pkt.data)
                        datapath.send_msg(out)
                        self.add_flow(datapath, match, actions)
                    else: 
                        flow_actions = []
                        for port in self.mult_to_port[dpid][dst_ip]: 
                            match = parser.OFPMatch(in_port=msg.in_port, dl_dst=dst)
                            if port != msg.in_port:
                                flow_actions.append(parser.OFPActionOutput(port))
                                send_actions = [parser.OFPActionOutput(port)]
                                out = parser.OFPPacketOut(datapath=datapath, 
                                        buffer_id=ofproto.OFP_NO_BUFFER, 
                                        in_port=ofproto.OFPP_CONTROLLER,
                                        actions=send_actions, data=pkt.data)
                                datapath.send_msg(out)
                            self.add_flow(datapath, match, flow_actions)

            # not a multicast packet
            else:
                self.mac_to_port[dpid][src] = msg.in_port
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD
                match = parser.OFPMatch(in_port=msg.in_port, dl_dst=dst)
                actions = [parser.OFPActionOutput(out_port)]
                if out_port != ofproto.OFPP_FLOOD:
                    self.add_flow(datapath, match, actions)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, 
                                    in_port=msg.in_port, actions=actions, data=data)
                datapath.send_msg(out)
                
        elif dpid == 0x1A:
            if ethertype == ARP:           # ARP packet
                arp_packet = pkt.get_protocols(arp.arp)
                if arp_packet[0].opcode==1:
                    self.send_arp_reply(  datapath, msg.in_port, 
                                            arp_packet[0].dst_ip, 
                                            arp_packet[0].src_ip, 
                                            dst, src)
            elif ethertype == IP:           # IP packet
                self.forward_from_1A(datapath, msg)
        elif dpid == 0x1B:
            if ethertype == ARP:           # ARP packet
                arp_packet = pkt.get_protocols(arp.arp)
                if arp_packet[0].opcode==1:
                    self.send_arp_reply(  datapath, msg.in_port, 
                                            arp_packet[0].dst_ip, 
                                            arp_packet[0].src_ip, 
                                            dst, src)
            elif ethertype == IP:         # IP packet
                self.forward_from_1B(datapath, msg)

    # Router 1A forwarding.
    # Only works for the topology given in the according lab.
    # Variable dest is the host's hardcoded mac address.
    # In the topology given each host has a mac that is the hex representation
    # of the last byte of the host ip address.
    def forward_from_1A(self, datapath, msg):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        p = packet.Packet(msg.data)
        ip_packet = p.get_protocols(ipv4.ipv4)
        outport = 3-msg.in_port
        data=msg.data
        
        # destination is network 2
        if (ip_packet[0].dst[:10]==NET2[:10]):
            match = parser.OFPMatch(nw_dst=ip_packet[0].dst, nw_dst_mask=24, dl_type=0x800)
            actions = [parser.OFPActionSetDlDst(S1B_LEFT_MAC),
                       parser.OFPActionSetDlSrc(S1A_RIGHT_MAC),
                       parser.OFPActionOutput(outport)]
            out = parser.OFPPacketOut(datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions, data=p.data)
            datapath.send_msg(out)
            self.add_flow(datapath, match, actions)
        
        # destination is network 1
        elif (ip_packet[0].dst[:10] == NET1[:10]
        and ip_packet[0].src[:10] == NET2[:10]):
            match = parser.OFPMatch(nw_dst=ip_packet[0].dst, dl_type=0x800)
            dest = S1A_LEFT_MAC[0:15]
            dest += str(hex(int(ip_packet[0].dst.split(".")[3])))[2:].zfill(2)
            actions = [parser.OFPActionSetDlDst(dest),
                       parser.OFPActionSetDlSrc(S1A_LEFT_MAC),
                       parser.OFPActionOutput(outport)]
            out = parser.OFPPacketOut(datapath=datapath, 
                    buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, 
                    actions=actions, data=p.data)
            datapath.send_msg(out)
            self.add_flow(datapath, match, actions)
        
        # drop the packet in any other case and add a flow for it too :)
        # since we proactively add multicast for range 239.0.0.0 to 239.0.0.3
        # we should either:
        #   i) check if the packet is a multicast packet and forward or not to s1b.
        # or ii) add proactive flows for all multicast traffic between s1a and s1b.
        # The code below implements another option: it drops all packets that are 
        # not requested to be handled by the homework.
        '''else:
            print("1a: packet was dropped and a flow was added.")
            match = parser.OFPMatch(nw_dst=ip_packet[0].dst, dl_type=0x800)
            actions = []
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=0,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
            datapath.send_msg(mod)'''

    # Router 1B forwarding.
    # Only works for the topology given in the according lab.
    # variable dest is the host's hardcoded mac address
    def forward_from_1B(self, datapath, msg):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        p = packet.Packet(msg.data)
        ip_packet = p.get_protocols(ipv4.ipv4)
        outport = 3-msg.in_port
        data = msg.data

        # destination is network 1
        if (ip_packet[0].dst[:10]==NET1[:10]):
            match = parser.OFPMatch(nw_dst=ip_packet[0].dst, nw_dst_mask=24, dl_type=0x800)
            actions = [parser.OFPActionSetDlDst(S1A_RIGHT_MAC),
                       parser.OFPActionSetDlSrc(S1B_LEFT_MAC),
                       parser.OFPActionOutput(outport)]
            out = parser.OFPPacketOut( datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=p.data)
            datapath.send_msg(out)
            self.add_flow(datapath, match, actions)
            
        # destination is network 2
        elif (ip_packet[0].dst[:10]==NET2[:10]
        and ip_packet[0].src[:10] == NET1[:10]):
            match = parser.OFPMatch(nw_dst=ip_packet[0].dst, dl_type=0x800)
            dest = S1B_RIGHT_MAC[:15]
            dest += str(hex(int(ip_packet[0].dst.split(".")[3])))[2:].zfill(2)
            actions = [parser.OFPActionSetDlDst(dest),
                       parser.OFPActionSetDlSrc(S1B_RIGHT_MAC),
                       parser.OFPActionOutput(outport)]
            out = parser.OFPPacketOut(datapath=datapath, 
                    buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions, data=p.data)
            datapath.send_msg(out)
            self.add_flow(datapath, match, actions)

        # drop the packet in any other case and add a flow for it too :)
        # since we proactively add multicast for range 239.0.0.0 to 239.0.0.3
        # we should either:
        # i) check if the packet is a multicast packet and forward or not to s1b.
        # OR ii) add proactive flows for all multicast traffic between s1a and s1b.
        # The code below implements another option: it drops all packets that are 
        # not requested to be handled by the homework.
        '''else:
            print("1b: packet was dropped and a flow was added.")
            match = parser.OFPMatch(nw_dst=ip_packet[0].dst, dl_type=0x800)
            actions = []
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=0,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
            datapath.send_msg(mod)'''


    # Constructs and sends an arp reply.
    # Assumes the topology given.
    def send_arp_reply(self, datapath, out_port, dst_ip, src_ip, dst, src):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if dst_ip == S1A_NET1_IP:
            e = ethernet.ethernet(dst=src, src=S1A_LEFT_MAC, ethertype=ARP)
            a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2, 
                        src_mac=S1A_LEFT_MAC, dst_mac=src, 
                        src_ip=S1A_NET1_IP, dst_ip=src_ip)
        elif dst_ip == S1B_NET2_IP:
            e = ethernet.ethernet(dst=src, src=S1B_RIGHT_MAC, ethertype=ARP)
            a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2, 
                        src_mac=S1B_RIGHT_MAC, dst_mac=src, 
                        src_ip=S1B_NET2_IP, dst_ip=src_ip)
        else: 
            return
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, 
                    buffer_id=ofproto.OFP_NO_BUFFER, 
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions, data=p.data)
        datapath.send_msg(out)


    # This function is called when the switch receives a multicast-subscribe
    # packet, to set the out ports for this multicast address.
    # For every new multicast address, one of the out ports will be the 
    # port 1, since 1 is the port to the router.
    # These checks are a bit complicated since Python was throwing errors
    # for not declared stuff.
    # Returns True if any port was added. False otherwise.
    def learn_subscribers_ports(self, in_port, multicast_ip, dpid):
        
        # add a new multicast ip to the switch table
        if multicast_ip not in self.mult_to_port[dpid]:
            self.mult_to_port[dpid][multicast_ip] = [1]
            print("Switch " + hex(dpid) + ": added port 1 for " 
                            + multicast_ip+" in switch table")
            
            # add the msg.in_port for the new multicast
            if in_port not in self.mult_to_port[dpid][multicast_ip]:
                print("Switch " + hex(dpid) + ": added port " + str(in_port)
                                + " for "+ multicast_ip+" in switch table")
                self.mult_to_port[dpid][multicast_ip].append(in_port)
        
        # add the msg.in_port for existent multicast
        elif in_port not in self.mult_to_port[dpid][multicast_ip]:
            print("Switch " + hex(dpid) + ": added port "+ str(in_port) 
                            + " for "+ multicast_ip+" in switch table")
            self.mult_to_port[dpid][multicast_ip].append(in_port)
        else: 
            print("Switch " + hex(dpid) + ": No action needed. Port "
                            + str(in_port) + " for " + multicast_ip
                            + " is already in switch table")
            return False        
        return True
        
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

    
    # Since the 24th bit of a multicast mac is always 0 we do a logical AND
    # between the second part of the ip and the number 127=01111111
    # zfill just adds a leading 0 if necessary.
    def multicast_ip_to_mac(self, ip):
        ip = ip.split('.')
        mac = MULTICAST_MAC_PREFIX + ':'
        mac += (str(int(ip[1]) & 127)).zfill(2) + ':'
        mac += (str(int(ip[2]))).zfill(2) + ':'
        mac += (str(int(ip[3]))).zfill(2)
        return mac
    