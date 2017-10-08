#!/usr/bin/python3 -u

# IFTTT Webhook for suspending/waking up a windows PC


import argparse
import configparser
import pprint
pp = pprint.PrettyPrinter(width=1)
import binascii
import socket
import struct
import http.server
import socketserver
import ssl
import os.path
import cgi
import json
import time
import subprocess


helptext = """webhook.py webserver for IFTTT json requests"""
parser = argparse.ArgumentParser(description=helptext)
parser.add_argument("-v", "--verbose", action="store_true",
    help="""verbose output""")
parser.add_argument("-m", "--mock", action="store_true",
    help="""don't actually cause any actions within the network""")
parser.add_argument('command', nargs='?', help="""command to execute directly instead of starting the server""")
args = parser.parse_args()


config = configparser.ConfigParser()
config.read('webhook.ini', encoding='utf-8')

WIN_PC = config['suspend']['WIN_PC']
WIN_USER = config['suspend']['WIN_USER']
SSH_USER = config['suspend']['SSH_USER']

MAC = config['wake']['MAC']
BROADCAST_IP = WIN_PC   # '255.255.255.255'
DEFAULT_PORT = int(config['wake']['PORT'])

SSL_DIR = config['webhook']['SSL_DIR']
SSL_KEY = config['webhook']['SSL_KEY']
SSL_CERT = config['webhook']['SSL_CERT']
HTTPS_PORT = int(config['webhook']['HTTPS_PORT'])
PASSWORD = config['webhook']['PASSWORD']


# From https://github.com/remcohaszing/pywakeonlan/blob/master/wakeonlan.py

def create_magic_packet(macaddress):
    """
    Create a magic packet.
    A magic packet is a packet that can be used with the for wake on lan
    protocol to wake up a computer. The packet is constructed from the
    mac address given as a parameter.
    Keyword arguments:
    :arg macaddress: the mac address that should be parsed into a magic
                     packet.
    """
    if len(macaddress) == 12:
        pass
    elif len(macaddress) == 17:
        sep = macaddress[2]
        macaddress = macaddress.replace(sep, '')
    else:
        raise ValueError('Incorrect MAC address format')

    # Pad the synchronization stream
    data = b'FFFFFFFFFFFF' + (macaddress * 16).encode()
    send_data = b''

    # Split up the hex values in pack
    for i in range(0, len(data), 2):
        send_data += struct.pack(b'B', int(data[i: i + 2], 16))
    return send_data


def send_magic_packet(*macs, **kwargs):
    """
    Wake up computers having any of the given mac addresses.
    Wake on lan must be enabled on the host device.
    Keyword arguments:
    :arguments macs: One or more macaddresses of machines to wake.
    :key ip_address: the ip address of the host to send the magic packet
                     to (default "255.255.255.255")
    :key port: the port of the host to send the magic packet to
               (default 9)
    """
    packets = []
    ip = kwargs.pop('ip_address', BROADCAST_IP)
    port = kwargs.pop('port', DEFAULT_PORT)
    for k in kwargs:
        raise TypeError('send_magic_packet() got an unexpected keyword '
                        'argument {!r}'.format(k))

    for mac in macs:
        packet = create_magic_packet(mac)
        packets.append(packet)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.connect((ip, port))
    if args.verbose:
        print("connected to " + ip)
    for packet in packets:
        sock.send(packet)
        if args.verbose:
            print("sent packet {0}".format(binascii.hexlify(packet)))
    sock.close()


 

class Handler(http.server.BaseHTTPRequestHandler):
    
    def sendresponse(self, code):
        self.send_response(code)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
    def do_GET(self):
        self.sendresponse(200)
        self.wfile.write("<html><head><title>IFTTT Webhook</title></head>".encode("utf-8"))
        self.wfile.write("<body><p>IFTTT Webhook</p>".encode("utf-8"))
        self.wfile.write("</body></html>".encode("utf-8"))

    def do_POST(self):
        if args.verbose:
            pp.pprint(self.headers.as_string())
        ctype, _ = cgi.parse_header(self.headers['content-type'])
        if ctype != 'application/json':
            self.sendresponse(400)
            return
        length = int(self.headers['content-length'])
        raw = self.rfile.read(length).decode('utf-8')
        msg = json.loads(raw)
        if args.verbose:
            pp.pprint(msg)
            
        if msg.get('password') != PASSWORD:
            print("Authentication failure")
            time.sleep(10)
            self.sendresponse(403)
            return

        if not command(msg.get('command')):
            self.sendresponse(400) 
        
        self.sendresponse(200) 
  

def command(cmd):
    """Only interpret known commands, otherwise return False."""
    if cmd == 'wake':
        wake()
    elif cmd == 'suspend':
        suspend()
    else:
        if not cmd is None:
            print("Unknown command {0}".format(cmd))
        return False
    return True

def wake():
    print("Wake up {0}".format(WIN_PC))
    if not args.mock:
        send_magic_packet(MAC)

def suspend():
    print("Suspend {0}".format(WIN_PC))
    cmd = "psshutdown -d -t 00 -v 00"   # requires the "Run as administrator" option
    ssh = "su {0} -c 'ssh {1}@{2} \"{3}\" '".format(SSH_USER, WIN_USER, WIN_PC, cmd)
    if args.verbose:
        print(ssh)
    if not args.mock:
        try:
            subprocess.run(ssh, shell=True, timeout=10)
        except subprocess.TimeoutExpired:
            pass
    

def start_http():
    httpd = socketserver.TCPServer(("", HTTPS_PORT), Handler)
    httpd.socket = ssl.wrap_socket(httpd.socket, 
                                   keyfile=os.path.join(SSL_DIR, SSL_KEY),
                                   certfile=os.path.join(SSL_DIR, SSL_CERT), 
                                   server_side=True)
    print("Starting the webhook.py server")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == '__main__':
    if not command(args.command):
        start_http()
