
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import pcaplib
from ryu.lib.packet import ipv4

#from dpkt import dpkt.dns
import dpkt


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.pcap_writer=pcaplib.Writer(open('mypcap3.pcap','wb'))
        self.blockthis={"anonimity.com":0}
        self.allsites={}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        not_allowed=False
        ip=pkt.get_protocol(ipv4.ipv4)
        if ip:
            
            self.pcap_writer.write_pkt(msg.data)
            pcap0=dpkt.pcap.Reader(open('mypcap3.pcap','rb'))
              
            if pcap0:
                for ts,buf in pcap0:
                    eth0=dpkt.ethernet.Ethernet(buf)
                    ip0=eth0.data
                    #self.logger.info("*******************************************************")
                    #self.logger.info("The logger ip packet %s",ip0)
                    if ip0.p:
                        #self.logger.info("")
                        if ip0.p!=17:
                        
                            continue
                        try:
                            #self.logger.info("************************************ ip0.p is %s", ip0.p)
                            udp=ip0.data
                        except:
                            continue
                        if udp.sport!= 53 and udp.dport!=53:
                            continue
                        try:
                            
                            dns=dpkt.dns.DNS(udp.data)
                           # self.logger.info("************************************ dns packet %s",dns)
                        except:
                            continue
                        if dns.qr!=dpkt.dns.DNS_R:
                            continue
                        if dns.opcode!=dpkt.dns.DNS_QUERY:
                            #self.logger.info("#################################### The qr %s",dns.qr)
                            continue
                        if dns.rcode!=dpkt.dns.DNS_RCODE_NOERR:
                            continue
                        #if len(dns.an)&lt; 1:
                            #continue
                        for qname in dns.qd:
                            self.logger.info("The domain name ************** %s ",qname.name)
                            if qname.name in self.blockthis:
                                not_allowed=True
                                self.blockthis[qname.name]+=1
                            else if qname.name in self.allsites:
                                self.allsites[qname.name]+=1
                            else:
                                self.allsites[qname.name]=0
            else:
                self.logger.info("NO PCAP **********************************")

        self.logger.info("########################")
        self.logger.info("Sites visited    %s",self.allsites.keys())
        if not_allowed==False:
            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                # ignore lldp packet
                return
            dst = eth.dst
            src = eth.src

            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
