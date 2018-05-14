from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.recoco import Timer
import time
import random
from threading import Lock
import numpy as np

# Create logger
log = core.getLogger()

class LoadBalancer(object):

    def __init__(self, service_ip, server_ips = []):
        ''' Class initializer. '''
        core.openflow.addListeners(self)
        self.service_ip = service_ip
        self.server_ips = server_ips

        # Dict for servers, with IPs as keys and (mac,port) as values
        self.servers_ip_to_macport = {}
        # Dict for known servers, with IPs as keys and (mac,port) as values
        self.clients_ip_to_macport = {}

    def choose_server(self, params = {}):
        print("Method not implemented.")
        
    def send_proxied_arp_request(self, connection, ip):
        ''' Send ARP request from the load balancer. '''
        arp_query = arp()
        arp_query.opcode = arp_query.REQUEST
        arp_query.hwtype = arp_query.HW_TYPE_ETHERNET
        arp_query.prototype = arp_query.PROTO_TYPE_IP
        arp_query.hwlen = 6
        arp_query.protodst = ip
        arp_query.protosrc = self.service_ip

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = ETHER_BROADCAST
        ether.src = self.lb_mac
        ether.set_payload(arp_query)

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        connection.send(msg)

    def _handle_ConnectionUp(self, event):
        ''' Prepare the controller upon switch connection.'''
        # Fake load balancer MAC
        self.lb_mac = EthAddr("A0:00:00:00:00:01")
        self.connection = event.connection
        # ARP queries for server MAC
        for i in self.server_ips:
            self.send_proxied_arp_request(self.connection, i)

    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        ''' Send ARP reply from the load balancer. '''
        arp_query = arp()
        arp_query.hwsrc = requested_mac
        arp_query.hwdst = packet.src
        arp_query.opcode = arp_query.REPLY
        arp_query.prototype = arp_query.PROTO_TYPE_IP
        arp_query.protosrc = packet.payload.protodst#self.service_ip
        arp_query.protodst = packet.payload.protosrc

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = packet.src
        ether.src = self.lb_mac
        ether.set_payload(arp_query)
        
        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = outport))
        connection.send(msg)

    def install_flow_rule_client_to_server(self, connection, outport, client_ip, server_ip, buffer_id=of.NO_BUFFER):
        ''' Create a table flow entry from clients to servers. '''
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x800
        fm.match.nw_dst = self.service_ip
        fm.match.nw_src = client_ip
        fm.buffer_id = buffer_id
        fm.idle_timeout = 3
        (server_mac, server_port) = self.servers_ip_to_macport[server_ip]
        fm.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        fm.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        fm.actions.append(of.ofp_action_output(port = outport))
        connection.send(fm)
        log.debug("Install flow, server %s, client %s" % (str(server_ip), str(client_ip)))

    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        ''' Create a table flow entry from servers to clients. '''
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x800
        fm.match.nw_dst = client_ip
        fm.match.nw_src = server_ip
        fm.buffer_id = buffer_id
        fm.idle_timeout = 3
        fm.actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
        fm.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        (client_mac, client_port) = self.clients_ip_to_macport[client_ip]
        fm.actions.append(of.ofp_action_dl_addr.set_dst(client_mac))
        fm.actions.append(of.ofp_action_output(port = outport))
        connection.send(fm)
        log.debug("Install flow, server %s, client %s" % (str(server_ip), str(client_ip)))

    def resend_packet(self, connection, packet_in, outport):
        ''' Resend a packet to a specific port. '''
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port = outport)
        msg.actions.append(action)
        connection.send(msg)

    def _handle_PacketIn(self, event):
        ''' Deal with packets for which there is no match in the flow table. '''
        packet = event.parsed
        connection = event.connection
        inport = event.port
        
        if packet.type == packet.ARP_TYPE:
            srcip = packet.payload.protosrc
            dstip = packet.payload.protodst
            # Check for reply ARP 
            if packet.payload.opcode == arp.REPLY:
                if srcip in self.server_ips:
                    # Update servers table
                    self.servers_ip_to_macport[srcip] = (packet.src, inport)            
            # Check for request ARP
            if packet.payload.opcode == arp.REQUEST:
                # Keep the client information
                if srcip not in self.server_ips:
                    self.clients_ip_to_macport[srcip] = (packet.src, inport)
                    self.send_proxied_arp_reply(packet, connection, inport, self.lb_mac)
                if srcip in self.server_ips:
                    if packet.payload.protodst in self.clients_ip_to_macport:
                        self.send_proxied_arp_reply(packet, connection, inport, self.lb_mac)
        
        elif packet.type == packet.IP_TYPE:
            srcip = packet.payload.srcip
            dstip = packet.payload.dstip
            if srcip in self.clients_ip_to_macport and dstip == self.service_ip:
                chosen_server = self.choose_server()
                (server_mac, server_port) = self.servers_ip_to_macport[chosen_server]
                self.install_flow_rule_client_to_server(self.connection, server_port, srcip, chosen_server)
                (client_mac, client_port) = self.clients_ip_to_macport[srcip]
                self.install_flow_rule_server_to_client(self.connection, client_port, chosen_server, srcip)
                # Resend the in_packet 
                packet.payload.dstip = chosen_server
                packet.dst = server_mac
                self.resend_packet(self.connection, packet, server_port)
        else:
            log.info("Unknown Packet type: %s" % packet.type)
        return

class RandomLoadBalancer(LoadBalancer):
    ''' Random load balancer. '''

    def choose_server(self, params = {}):
        return list(self.servers_ip_to_macport.keys())[random.randint(0, len(self.server_ips))]

class StatsLoadBalancer(LoadBalancer):
    ''' Statistics load balancer. '''

    def __init__(self, service_ip, server_ips = [], print_stats=False):
        super(StatsLoadBalancer, self).__init__(service_ip, server_ips)
        # Lock for flows stats
        self.lock_flows = Lock()
        # Lock for port stats
        self.lock_port = Lock()
        # Flow packets statistics
        self.server_pack_stats = {}
        # Lost port packets statistics
        self.server_port_loss_stats = {}
        # Update interval
        self.update_interval = 2
        # Print flows
        self.print_stats = print_stats
        # Register flow statistics handler
        core.openflow.addListenerByName("FlowStatsReceived", self.handle_flow_stats)
        core.openflow.addListenerByName("PortStatsReceived", self.handle_port_stats)
        # Timer
        Timer(self.update_interval, self.request_server_pack_stats, recurring=True)

    def _handle_ConnectionUp(self, event):
        super(StatsLoadBalancer, self)._handle_ConnectionUp(event)
        # Initialize packet flow stats
        self.lock_flows.acquire()
        for s in self.server_ips:
            self.server_pack_stats[s] = (0, [])
        self.lock_flows.release()


    def request_server_pack_stats(self):
        ''' To be executed in a timer. '''
        # Request statistics
        try:
            req = of.ofp_stats_request(body=of.ofp_flow_stats_request())
            self.connection.send(req)
            req = of.ofp_stats_request(body=of.ofp_port_stats_request())
            self.connection.send(req)
        except:
            log.info("Failed to send the statistics request.")

    def handle_flow_stats(self, event):
        flows = event.stats
        # Initialize current count
        current_packet_count = dict(zip(self.server_ips, [0]*len(self.server_ips)))
        # Search flows to servers
        for flow in flows:
            # Check flow is from client
            src = flow.match.nw_src 
            dst = flow.match.nw_dst

            if src in self.clients_ip_to_macport and dst == self.service_ip:
                # Discover server destination
                for action in flow.actions:
                    if action.type == of.OFPAT_SET_NW_DST:
                        server_ip = action.nw_addr
                        break
                # If server discovered
                if server_ip:
                    if flow.packet_count > 0:
                        current_packet_count[server_ip] += flow.packet_count

        # Process
        self.lock_flows.acquire()
        for s in self.server_pack_stats:
            last, lst = self.server_pack_stats[s]
            if lst is not None:
                if s in current_packet_count:
                    cur = current_packet_count[s]
                    if len(lst) == 10: 
                        del lst[0]
                    lst.append(max(0,cur - last))
                    self.server_pack_stats[s] = (cur, lst)
                else:
                    self.server_pack_stats[s] = (0, lst.append(0))
        if self.print_stats:
            print("Flow stats: " + str(self.server_pack_stats))
        self.lock_flows.release()
                
    def handle_port_stats(self, event):
        ports = event.stats
        self.lock_port.acquire()
        for port in ports:
            #print(self.server_ports)
            #if port.port_no not in self.server_ports: 
            #    continue
            if port.port_no not in self.server_port_loss_stats:
                self.server_port_loss_stats[port.port_no] = (0, 0, [])
            (last_tx, last_rx, lst) = self.server_port_loss_stats[port.port_no]
            if len(lst) == 5: 
                del lst[0]
            lst.append((port.tx_dropped - last_tx, port.rx_dropped - last_rx))
            self.server_port_loss_stats[port.port_no] = (port.tx_dropped, port.rx_dropped, lst)
        if self.print_stats:
            print("Port stats:" + str(self.server_port_loss_stats))
        self.lock_port.release()

    def choose_server(self, params = {}):
        '''
        Scoring: S = 0.7 * packet_flow + 0.3 * (0.4 * rx_loss + 0.6 * tx_loss)
        Selects the server with the least score.
        '''
        server_scores = dict(zip(self.server_ips, [0]*len(self.server_ips)))
        # Compute scores
        for s in server_scores:
            (mac,port) = self.servers_ip_to_macport[s]
            # Score fraction for por loss 
            self.lock_port.acquire()
            if port in self.server_port_loss_stats:
                lst = self.server_port_loss_stats[port][2]
                port_loss_score = 0.0 
                mean_rx = 0.0
                mean_tx = 0.0
                for (tx_loss, rx_loss) in lst:
                    mean_rx += float(rx_loss)/len(lst)
                    mean_tx += float(tx_loss)/len(lst)
                port_loss_score = mean_rx * 0.4 + mean_tx * 0.6 
                server_scores[s] += 0.3 * port_loss_score
            self.lock_port.release()
            # Score fraction for packet flow
            self.lock_flows.acquire()
            if s in self.server_pack_stats:
                if self.server_pack_stats[s][1]:
                    server_scores[s] += 0.7 * np.mean(self.server_pack_stats[s][1])
            self.lock_flows.release()
        # Return with the least score
        chosen = min(server_scores, key=server_scores.get)
        log.debug("Scores: " + str(server_scores))
        log.debug("Server chosen: " + str(chosen) + " - with score " + str(server_scores[chosen]))
        return chosen

def launch(ip, servers, type_controller, print_stats):
    ''' Launch the controller. '''
    server_ips = servers.replace(",", " ").split()
    server_ips = [IPAddr(x) for x in server_ips]
    service_ip = IPAddr(ip)
    log.debug("Loading " + str(type_controller) + " module")
    # Controller type
    if type_controller == "random":
        core.registerNew(RandomLoadBalancer, service_ip, server_ips)
    elif type_controller == "stats":
        core.registerNew(StatsLoadBalancer, service_ip, server_ips, (print_stats == "True"))


