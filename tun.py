import os
import fcntl
import struct
from scapy.all import IP, TCP
import threading
import sockslib
import tcplib
import traceback

# Might need to be run as admin first time
os.system("ip tuntap add dev tun0 mode tun")
os.system("ip link set tun0 up")
os.system("ip addr add 172.16.0.1/32 dev tun0")

# Constants for the TUN device
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

# Open file descriptor for the TUN device
tun_fd = os.open('/dev/net/tun', os.O_RDWR)

# Prepare the struct for ioctl call to create a TUN device named 'tun0'
ifr = struct.pack('16sH', b'tun0', IFF_TUN | IFF_NO_PI)

# Create TUN device
fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
            
session_handler = tcplib.TCPSessionHandler(tun_fd)

def preEstablish(session):
    # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = sockslib.SocksSocket()
    sock.set_proxy(('127.0.0.1', 9050))
    try:
        sock.connect((session.dst_ip, session.dst_port))
        session.sock = sock
        return True
    except:
        return False

def forward(session: tcplib.TCPSession):
    while session.is_open():
        data = session.sock.recv(1024)

        if data == b'':
            session.close()
        session.send_data(data)

def onEstablish(session, _):
    threading.Thread(
        target=forward,
        args=[session],
        daemon=True
    ).start()

def onData(session: tcplib.TCPSession, data):
    session.sock.sendall(data[TCP].load)

session_handler.on("data", onData)
session_handler.on("syn_received", preEstablish)
session_handler.on("tcp_establish", onEstablish)

session_handler.on("debug", lambda session, msg: print(msg))

try:
    while True:
        packet = os.read(tun_fd, 2048)
        ip = IP(packet)
        
        # check if the packet is a TCP packet
        if ip.proto != 6:
            continue

        try:
            session_handler.handle_packet(ip)
        except RuntimeError:
            pass
        except:
            traceback.format_exc()
except KeyboardInterrupt:
    os.system("ip link delete tun0")
    os.close(tun_fd)
    print("Exiting...")

