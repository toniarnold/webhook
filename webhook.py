#!/usr/bin/python3 -u

helptext = """IFTTT Webhook for json requests to control a windows PC.
Supported commands: wake, suspend, poweroff, poweroff_linux, reboot_linux"""


import argparse
import configparser
import pprint
pp = pprint.PrettyPrinter(width=1)
import logging
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


parser = argparse.ArgumentParser(description=helptext)
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("-m", "--mock", action="store_true",
    help="""don't actually cause any actions within the network""")
parser.add_argument('command', nargs='?',
    help="""command to execute directly instead of starting the server""")
parser.add_argument("-q", "--quiet", help="set logging to ERROR",
                    action="store_const", dest="loglevel",
                    const=logging.ERROR, default=logging.INFO)
parser.add_argument("-d", "--debug", help="set logging to DEBUG",
                    action="store_const", dest="loglevel",
                    const=logging.DEBUG, default=logging.INFO)
args = parser.parse_args()


config = configparser.ConfigParser()
config.read('webhook.ini', encoding='utf-8')

# WOL send_magic_packet conf
MAC = config['wake']['mac']
BROADCAST_IP = '255.255.255.255'  # for config['win']['host'] comment out sock.setsockopt below
DEFAULT_PORT = int(config['wake']['port'])


logging.basicConfig(level=args.loglevel,
                    format='%(levelname)-8s %(message)s')
_log = logging.getLogger('webhook')



# Command dispatcher and implementations

def command(cmd):
    """Command dispatcher. Only interpret known commands, otherwise return False."""
    if cmd is None:
        return False
    _log.info("Received command {0}".format(cmd))
    if cmd == 'wake':
        wake()
    elif cmd == 'suspend':
        suspend()
    elif cmd == 'poweroff':
        poweroff()
    elif cmd == 'poweroff_linux':
        poweroff_linux()
    elif cmd == 'reboot_linux':
        reboot_linux()
    else:
        _log.error("Unknown command {0}".format(cmd))
        return False
    return True

def wake():
    _log.debug("Wake up {0}".format(MAC))
    if not args.mock:
        send_magic_packet(MAC)

def suspend():
    _log.debug("Suspend {0}".format(config['win']['host']))
    remote_command("psshutdown -d -t 00 -v 00", 
                   config['win']['user'],
                   config['win']['host'])

def poweroff():
    _log.debug("Poweroff {0}".format(config['win']['host']))
    remote_command("psshutdown -k -t 00 -v 00", 
                   config['win']['user'],
                   config['win']['host'])

def poweroff_linux():
    _log.debug("Poweroff {0}".format(config['linux']['host']))
    remote_command("sudo chvt 1 ; sudo halt", 
                   config['linux']['user'],
                   config['linux']['host'])

def reboot_linux():
    _log.debug("Poweroff {0}".format(config['linux']['host']))
    remote_command("sudo chvt 1 ; sudo reboot", 
                   config['linux']['user'],
                   config['linux']['host'])


# SSH to the Windows PC

def remote_command(cmd, remote_user, remote_host):
    """Ececute a command on the remote host."""
    ssh = "su {0} -c 'ssh {1}@{2} \"{3}\" '".format(
            config['webhook']['ssh_user'], remote_user, remote_host, cmd)
    _log.debug(ssh)
    if not args.mock:
        try:
            subprocess.run(ssh, shell=True, timeout=30)
        except subprocess.TimeoutExpired:
            pass


# WOL from https://github.com/remcohaszing/pywakeonlan/blob/master/wakeonlan.py

def create_magic_packet(macaddress):
    """
    Create a magic packet.

    A magic packet is a packet that can be used with the for wake on lan
    protocol to wake up a computer. The packet is constructed from the
    mac address given as a parameter.

    Args:
        macaddress (str): the mac address that should be parsed into a
            magic packet.

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

    Args:
        macs (str): One or more macaddresses of machines to wake.

    Keyword Args:
        ip_address (str): the ip address of the host to send the magic packet
                     to (default "255.255.255.255")
        port (int): the port of the host to send the magic packet to
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
    # comment out for config['win']['host'] insead of 255.255.255.255:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.connect((ip, port))
    _log.debug("connected to {0}".format(ip))
    for packet in packets:
        sock.send(packet)
        _log.debug("sent packet {0}".format(binascii.hexlify(packet)))
    sock.close()



# HTTPS server

class Handler(http.server.BaseHTTPRequestHandler):
    
    def sendresponse(self, code):
        self.send_response(code)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
    def do_GET(self):
        """Only respond with a HTML page to GET requests in verbose mode"""
        if not args.verbose:
            self.sendresponse(400)
            return
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
            
        if msg.get('password') != config['webhook']['password']:
            _log.error("Authentication failure")
            time.sleep(10)
            self.sendresponse(403)
            return

        if not command(msg.get('command')):
            _log.error("Unknown command {0}".format(msg.get('command')))
            self.sendresponse(400)
            return
        
        self.sendresponse(200) 
  

def start_http():
    httpd = socketserver.TCPServer(("", int(config['webhook']['https_port'])), Handler)
    httpd.socket = ssl.wrap_socket(httpd.socket, 
       keyfile=os.path.join(config['webhook']['ssl_dir'], config['webhook']['ssl_key']),
       certfile=os.path.join(config['webhook']['ssl_dir'], config['webhook']['ssl_cert']), 
       server_side=True)
    _log.info("Starting the webhook.py server")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == '__main__':
    if args.command:
        command(args.command)
    else:
        start_http()
