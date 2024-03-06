import os
from .TCP import TCPFlags
from scapy.all import IP, TCP


# This pretends to be a server
class TCPSession: 
    def __init__(self, dispatcher, packet: IP):
        self.src_ip = packet.src
        self.dst_ip = packet.dst
        self.src_port = packet[TCP].sport
        self.dst_port = packet[TCP].dport
        self.state = 'SYN_RECEIVED'
        self.dispatcher = dispatcher

        # Always update ack before sending
        self.seq = packet[TCP].seq
        self.ack = packet[TCP].seq + 1
        if self.dispatcher.dispatch("syn_received", self):
            self.send_syn_ack()
            self.dispatcher.dispatch("debug", self, "Sent initial SYN/ACK")
            self.seq = packet[TCP].seq + 1
        else:
            self.close()
    
    def is_open(self):
        return self.state == "ESTABLISHED"

    def close(self):
        if self.state != "ESTABLISHED":
            self.state = 'CLOSED'
            self.dispatcher.dispatch("debug", self, "Session closed before establishment")
            self.dispatcher.sessions.remove(self)
            rst_packet = IP(src=self.dst_ip, dst=self.src_ip)/TCP(sport=self.dst_port, dport=self.src_port, flags=TCPFlags.RST, ack=self.ack, seq=self.seq)
            os.write(self.dispatcher.tun_fd, bytes(rst_packet))
        else:
            self.dispatcher.dispatch("debug", self, "Session closing...")
            self.state = 'CLOSE_WAIT'
            fin_ack_packet = IP(src=self.dst_ip, dst=self.src_ip)/TCP(sport=self.dst_port, dport=self.src_port, flags=TCPFlags.FIN|TCPFlags.ACK, ack=self.ack, seq=self.seq)
            os.write(self.dispatcher.tun_fd, bytes(fin_ack_packet))

    def send_syn_ack(self):
        syn_ack_packet = IP(src=self.dst_ip, dst=self.src_ip)/TCP(sport=self.dst_port, dport=self.src_port, flags=TCPFlags.SYN|TCPFlags.ACK, ack=self.ack, seq=self.seq)
        os.write(self.dispatcher.tun_fd, bytes(syn_ack_packet))

    def send_fin_ack(self):
        fin_ack_packet = IP(src=self.dst_ip, dst=self.src_ip)/TCP(sport=self.dst_port, dport=self.src_port, flags=TCPFlags.FIN|TCPFlags.ACK, seq=self.seq, ack=self.ack)
        os.write(self.dispatcher.tun_fd, bytes(fin_ack_packet))

    def send_ack(self):
        ack_packet = IP(src=self.dst_ip, dst=self.src_ip)/TCP(sport=self.dst_port, dport=self.src_port, flags=TCPFlags.ACK, seq=self.seq, ack=self.ack)
        os.write(self.dispatcher.tun_fd, bytes(ack_packet))
    
    def match(self, packet: IP):
        return (
            packet.src == self.src_ip and
            packet.dst == self.dst_ip and
            packet[TCP].sport == self.src_port and
            packet[TCP].dport == self.dst_port
        )
        
    def handle_packet(self, packet: IP):
        if packet[TCP].flags & TCPFlags.RST:
            self.state = 'CLOSED'
            self.dispatcher.sessions.remove(self)
            self.dispatcher.dispatch("debug", self, "Session closed via received RST")
            return

        if self.state == 'SYN_RECEIVED':
            if packet[TCP].flags & TCPFlags.ACK:
                self.state = 'ESTABLISHED'
                self.dispatcher.dispatch("tcp_establish", self, packet)
            elif packet[TCP].flags & TCPFlags.SYN:
                self.send_syn_ack()
        elif self.state == 'ESTABLISHED':
            self.handle_established(packet)
        elif self.state == 'CLOSE_WAIT':
            if packet[TCP].flags & TCPFlags.ACK: # Set state to closed and remove
                self.state == 'CLOSED'
                self.dispatcher.sessions.remove(self)
                self.dispatcher.dispatch("debug", self, "Session closed.")
    
    def handle_established(self, packet: IP):
        if packet[TCP].flags & TCPFlags.FIN:
            self.seq = packet[TCP].ack
            self.ack = packet[TCP].seq + 1
            self.send_fin_ack()
            self.state = 'CLOSE_WAIT'
        elif packet[TCP].flags & TCPFlags.PSH:
            self.seq = packet[TCP].ack
            self.ack = packet[TCP].seq + len(packet[TCP].load)
            self.send_ack()
            self.handle_data(packet)
        elif packet[TCP].flags & TCPFlags.ACK:
            self.seq = packet[TCP].ack
            self.ack = packet[TCP].seq
    
    def send_data(self, data: bytes):
        data_packet = IP(src=self.dst_ip, dst=self.src_ip)/TCP(sport=self.dst_port, dport=self.src_port, flags=TCPFlags.PSH|TCPFlags.ACK, seq=self.seq, ack=self.ack)/data
        os.write(self.dispatcher.tun_fd, bytes(data_packet))

    def handle_data(self, packet: IP):
        self.dispatcher.dispatch("data", self, packet)

class TCPSessionHandler:
    def __init__(self, tun_fd):
        self.sessions = []
        self.event_handlers = {
            "syn_received": lambda *args: True,           # Return true by default
            "debug":        lambda *args: True,           
            "all":          lambda *args, **kwargs: None
        }
        self.tun_fd = tun_fd

    def on(self, event, handler):
        self.event_handlers[event] = handler

    def dispatch(self, event, session, *args, **kwargs):
        self.event_handlers["all"](event, session, *args, **kwargs)
        return self.event_handlers[event](session, *args, **kwargs)     

    def handle_packet(self, packet: IP):
        for session in self.sessions:
            if session.match(packet):
                session.handle_packet(packet)
                return
        
        # Check if the packet is a SYN packet
        if packet[TCP].flags & TCPFlags.SYN:
            session = TCPSession(self, packet)
            self.sessions.append(session)
            return
        
        raise RuntimeError("Packet not matched in any TCP context")
