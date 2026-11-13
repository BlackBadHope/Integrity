# SPDX-License-Identifier: BUSL-1.1
"""LAB-only HTTPS CONNECT proxy. Never inspects TLS, cookies or URL paths."""
import argparse
import ipaddress
import json
import select
import socket
import socketserver
import threading
import time

# The listen address, port and the one permitted client come from the command line
# (windows_egress_setup.start passes the values from lab.json).
CLIENT = None
DOMAINS = ('openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com')
EXACT = {'challenges.cloudflare.com', 'cdn.auth0.com'}
SLOTS = threading.BoundedSemaphore(16)


def allowed_host(host):
    host = host.lower().rstrip('.')
    if len(host)>253 or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-.' for c in host):
        return False
    return host in EXACT or any(host == base or host.endswith('.'+base) for base in DOMAINS)


def global_address(address):
    ip=ipaddress.ip_address(address)
    return ip.is_global and not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        if self.client_address[0] != CLIENT or not SLOTS.acquire(blocking=False):
            return
        upstream=None
        host=None
        try:
            self.request.settimeout(10)
            data=b''
            while b'\r\n\r\n' not in data:
                chunk=self.request.recv(1024)
                if not chunk:return
                data+=chunk
                if len(data)>8192:
                    raise ValueError('header_limit')
            line=data.split(b'\r\n',1)[0].decode('ascii')
            method,authority,version=line.split(' ')
            if method!='CONNECT' or version not in {'HTTP/1.0','HTTP/1.1'}:
                raise ValueError('connect_only')
            host,port=authority.rsplit(':',1)
            host=host.lower().rstrip('.')
            if port!='443' or not allowed_host(host):
                raise ValueError('destination_policy')
            addresses=socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)
            if not addresses or not all(global_address(a[4][0]) for a in addresses):
                raise ValueError('non_global_DNS_answer')
            # Connect to the validated IP rather than resolving the name again.
            for family,kind,proto,_,address in addresses[:6]:
                trial=socket.socket(family,kind,proto);trial.settimeout(10)
                try:trial.connect(address);upstream=trial;break
                except OSError:trial.close()
            if upstream is None:raise OSError('upstream_unreachable')
            self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            tail=data.partition(b'\r\n\r\n')[2]
            if tail:upstream.sendall(tail)
            self.request.settimeout(15);upstream.settimeout(15)
            end=time.monotonic()+900
            while time.monotonic()<end:
                ready,_,_=select.select([self.request,upstream],[],[],60)
                if not ready:return
                for source in ready:
                    block=source.recv(65536)
                    if not block:return
                    (upstream if source is self.request else self.request).sendall(block)
        except (OSError,ValueError,UnicodeError) as error:
            # Deliberately exclude request lines, headers, query strings and TLS bytes.
            print(json.dumps({'decision':'DENY','host':host if host and allowed_host(host) else None,
                              'reason':str(error) if isinstance(error,ValueError) else 'connection_error'}),flush=True)
            try:self.request.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            except OSError:pass
        finally:
            if upstream:upstream.close()
            SLOTS.release()


class Server(socketserver.ThreadingMixIn,socketserver.TCPServer):
    allow_reuse_address=True
    daemon_threads=True
    request_queue_size=16


# First hosts of the private (RFC 1918), link-local, shared (RFC 6598) and unique-local
# ranges. They are written as integers because the public tree carries no literal
# non-documentation addresses.
RESERVED_SAMPLES = [str(ipaddress.IPv4Address(n)) for n in (0x0A000001, 0xAC100001, 0xC0A80001, 0xA9FE0001, 0x64400001)]
RESERVED_SAMPLES.append(str(ipaddress.IPv6Address((0xfc00 << 112) | 1)))
DOCUMENTATION_SAMPLES = ['192.0.2.20', '198.51.100.1', '203.0.113.5', '2001:db8::1']


def self_test(global_sample=None):
    assert all(allowed_host(x) for x in ['auth.openai.com','chatgpt.com','cdn.oaistatic.com','challenges.cloudflare.com'])
    assert all(not allowed_host(x) for x in ['chatgpt.com.attacker.invalid','notopenai.com','127.0.0.1','192.0.2.20','example.com','openai.com@127.0.0.1'])
    assert all(not global_address(x) for x in ['127.0.0.1','::1',*RESERVED_SAMPLES,*DOCUMENTATION_SAMPLES])
    # A positive global sample is operator-supplied; none is hard-coded here.
    if global_sample is not None:assert global_address(global_sample)
    print(json.dumps({'status':'PASS_POLICY_ONLY','claims':['domain_boundary','private_loopback_linklocal_denied','validated_IP_connect'],
                      'global_positive':'PASS' if global_sample is not None else 'NOT_RUN',
                      'real_network':'NOT_RUN','agents':'NOT_RUN','models':'NOT_RUN'}))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--global-sample');parser.add_argument('--listen');parser.add_argument('--port',type=int)
    parser.add_argument('--client');args=parser.parse_args()
    if args.self_test:self_test(args.global_sample)
    else:
        if not (args.listen and args.port and args.client):
            parser.error('--listen, --port and --client are required (values from lab.json)')
        CLIENT=args.client
        with Server((args.listen,args.port),Handler) as server:server.serve_forever(poll_interval=1)
