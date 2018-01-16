import netifaces
import socket
from socket import AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST
from time import sleep
import threading
import uuid

import secure

UDP_PORT = 50000
TCP_PORT = 10000
MAX_ANNOUNCE_MSGS = 500
announce_key = "plathjam" #to make sure we don't confuse or get confused by other programs
delims = ["_", "#", "$", "%"]

def report(msg, arg1=None, arg2=None, arg3=None):
    print msg

def get_netstats():
    netstats = []

    for i in netifaces.interfaces():
        got_mac = False
        got_net = False
        addrs = netifaces.ifaddresses(i)
        if (netifaces.AF_LINK in addrs):
            mac_ = str(addrs[netifaces.AF_LINK][0]['addr'])
            if (len(mac_) == 17):
                got_mac = True
        if (netifaces.AF_INET in addrs):
            for ifaddr in addrs[netifaces.AF_INET]:
                if 'addr' in ifaddr:
                    ip_ = str(addrs[netifaces.AF_INET][0]['addr'])
                    netmask_ = str(addrs[netifaces.AF_INET][0]['netmask'])
                    broadcast_ = str(addrs[netifaces.AF_INET][0]['broadcast'])
                    got_net = True
            if (netifaces.AF_INET6 in addrs):
                for ifaddr in addrs[netifaces.AF_INET6]:
                    if (('addr' in ifaddr) and (len(addrs[netifaces.AF_INET6][0]['addr']))):
                        ipv6_ = str(addrs[netifaces.AF_INET6][0]['addr'])
        if (got_net and got_mac):
            temp = []
            temp.append(mac_)
            temp.append(ip_)
            temp.append(ipv6_)
            temp.append(netmask_)
            temp.append(broadcast_)
            netstats.append(temp)   
            report ("Interface(s) found (MAC: " + mac_  +", IPv4: " + ip_ + ", IPv6: " + ipv6_ + ", Subnet Mask: " + netmask_ + ", Broadcast: " + broadcast_ + ")")

    return netstats
    
def start_TCP(ip, port):
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # Create a TCP/IP socket
    report("Starting server on %s:%s" % (my_ip, TCP_PORT))
    server_address = (my_ip, TCP_PORT) 
    tcp_sock.bind(server_address)   # Bind the socket to the port
    tcp_sock.listen(1)  # Listen for incoming connections

    while True:  
        report("Waiting for a connection...")
        connection, client_address = tcp_sock.accept()  # Wait for a connection
        try:
            report("Incoming connection from %s." % (client_address[0]))

            while True:
                data = connection.recv(16)  # Receive the data in small chunks and retransmit it                
                if data:
                    report("Received %d bytes: <%s>" % (len(data), data))
                    report("Echoing <%s> to %s" % (data, client_address[0]))
                    connection.sendall(data)
                else:
                    report("No more data from %s." % (client_address[0]))
                    break
                
        finally:
            connection.close()  # Clean up the connection

def start_UDP(ip, port, id, size):
    udp_sock = socket.socket(AF_INET, SOCK_DGRAM)  # Create a UDP socket
    udp_sock.bind(('', 0))  # Bind the socket to the port
    udp_sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    report("Starting announce server on %s:%s" % (my_ip, UDP_PORT))

    for i in range (0,MAX_ANNOUNCE_MSGS):
        data = ""
        data += str(len(announce_key))
        data += str(delims[0])
        data += str(announce_key)
        data += str(delims[1])
        data += str(len(str(ip)))
        data += str(delims[2])
        data += str(ip)
        data += str(delims[3])
        data += uuid.uuid4().hex
        signature = secure.create_signature(secure.passwd_sign, data)
        print signature
        print len(signature)
        data += signature
        data = secure.encrypt(secure.passwd_enc, data)
        print data
        print len(data)
        udp_sock.sendto(data, ('<broadcast>', UDP_PORT))
        report("Sending broadcast message... (%s/%s)" % (i+1, MAX_ANNOUNCE_MSGS))
        sleep(5)

my_ip = get_netstats()[0][1]

#encrypted = secure.encrypt(secure.passwd_enc, 'Secret Message ASecret Message A')
#print encrypted

#decrypted = secure.decrypt(secure.passwd_enc, encrypted)
#print decrypted

#signature = secure.create_signature(secure.passwd_sign, encrypted)
#print signature

#exit(1)

#start_TCP(my_ip, TCP_PORT)
#start_UDP(my_ip, UDP_PORT, MAGIC, MAX_ANNOUNCE_MSGS)

d_tcp_srv = threading.Thread(name='tcp_daemon', target=start_TCP, args=(my_ip, TCP_PORT))
d_tcp_srv.setDaemon(False)

d_udp_srv = threading.Thread(name='udp_daemon', target=start_UDP, args=(my_ip, UDP_PORT, announce_key, MAX_ANNOUNCE_MSGS))
d_udp_srv.setDaemon(True)

d_tcp_srv.start()
d_udp_srv.start()

#exit(1)    





    
