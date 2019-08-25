from threading import *
from time import sleep
import socket
from scapy.all import *
import sys

try:
    host_ip = socket.gethostbyname(sys.argv[1])

except socket.gaierror:
    print("there was an error resolving the host")
    sys.exit()
ip_host=host_ip
ip='ip host '+ip_host


class sniffer(Thread):
    def run(self):
        ans = sniff(filter=ip, count=2)
        flag = (ans[1][TCP].flags)
        if 'E' in flag:

            print(sys.argv[1] ,','+host_ip+',','YES')
        else:
            print(sys.argv[1],','+host_ip+',','NO')


class tcp_handshake(Thread):
    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        except socket.error as err:
            print("socket creation failed with error %s" % (err))
        port = 80
        s.connect((host_ip, port))


thread_s=sniffer()
thread_t=tcp_handshake()

thread_s.start()
sleep(2)
thread_t.start()


