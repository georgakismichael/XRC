from time import sleep
from socket import socket, AF_INET, SOCK_DGRAM

import secure

UDP_PORT = 50000
TCP_PORT = 10000
announce_key = "plathjam" #to make sure we don't confuse or get confused by other programs
delims = ["_", "#", "$", "%"]

s = socket(AF_INET, SOCK_DGRAM) #create UDP socket
s.bind(('', UDP_PORT))

timeout = 0
data_announce_ip = None

while timeout < 3:
    data, addr = s.recvfrom(256) #wait for a packet
    data = secure.decrypt(secure.passwd_enc, data)
    print "Received and decrypted " + str(len(data)) + " bytes..."
    signature = data[len(data)-40:]
    calc_sign = secure.create_signature(secure.passwd_sign, data[:len(data)-40])
    if (calc_sign == signature):
        print "Message authenticated..."
    else:
        print "Message failed to authenticate!"
        continue
        
    data_announce_key_sz = data.split(str(delims[0]))[0]
    data_announce_key = data[len(data_announce_key_sz) + len(str(delims[0])):len(data_announce_key_sz) + len(str(delims[0])) + len(announce_key)]

    if (announce_key == data_announce_key):
    
        data = data.split(str(delims[1]))[1]

        data_announce_ip_sz = int(data.split(str(delims[2]))[0])
        data_announce_ip = str(data[len(str(data_announce_ip_sz)) + len(str(delims[2])):len(str(data_announce_ip_sz)) + len(str(delims[2])) + data_announce_ip_sz])
        
        print "Got service announcement from " + data_announce_ip
        
        break
    elif data:
        print data
        print len(data)
    else:
        sleep(0.5)
        
    if not data_announce_ip:
        timeout = 0
        continue

import socket
import sys

#for i in range (1000):
while 1:
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (data_announce_ip, TCP_PORT)
    print >>sys.stderr, 'connecting to %s port %s' % server_address
    sock.connect(server_address)

    try:
        
        # Send data
        message = 'This is the message.  It will be repeated.'
        print >>sys.stderr, 'sending "%s"' % message
        sock.sendall(message)

        # Look for the response
        amount_received = 0
        amount_expected = len(message)
        
        while amount_received < amount_expected:
            data = sock.recv(16)
            amount_received += len(data)
            print >>sys.stderr, 'received "%s"' % data

    finally:
        print >>sys.stderr, 'closing socket'
        sock.close()
    sleep(0.3)
