#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import getoutput
from dnslib.label import DNSLabel
from dnslib.server import UDPServer, TCPServer, DNSHandler,BaseResolver,DNSLogger
from dnslib import parse_time,RR, QTYPE,A,AAAA,TXT,RCODE,PTR
import socket
from ipaddress import ip_address
import binascii,socket,struct,threading,time


class ShellResolver(BaseResolver):
    """
        Example dynamic resolver.
        Maps DNS labels to shell commands and returns result as TXT record
        (Note: No context is passed to the shell command)

        Shell commands are passed in a a list in <label>:<cmd> format - eg:

            [ 'uptime.abc.com.:uptime', 'ls:ls' ]

        Would respond to requests to 'uptime.abc.com.' with the output
        of the 'uptime' command.

        For non-absolute labels the 'origin' parameter is prepended

    """
    def __init__(self,routes,origin,ttl):
        self.origin = DNSLabel(origin)
        self.ttl = parse_time(ttl)
        self.routes = {}
        for r in routes:
            route,_,cmd = r.partition(":")
            if route.endswith('.'):
                route = DNSLabel(route)
            else:
                route = self.origin.add(route)
            self.routes[route] = cmd

    def resolve(self,request,handler):
        print("resolver:" + "-"*40)
        reply = request.reply()
        qname = request.q.qname
        ia = ip_address(handler.client_address[0])
        cmd = self.routes.get(qname)
        if cmd:
            output = getoutput(cmd).encode()
            reply.add_answer(RR(qname,QTYPE.TXT,ttl=self.ttl,
                                rdata=TXT(output[:254])))
        else:
            rqt = QTYPE.TXT
            rqd = TXT(f"{str(ia)}")
            if request.q.qtype in [QTYPE.A,QTYPE.AAAA,QTYPE.PTR]:
                QTR = { QTYPE.A : "A", QTYPE.AAAA : "AAAA", QTYPE.PTR : "PTR" }
                qt = QTR[request.q.qtype]
                if ia.version is 6 and request.q.qtype == QTYPE.AAAA:
                    rqt = request.q.qtype
                    rqd = AAAA(str(ia))
                elif ia.version is 4 and request.q.qtype == QTYPE.A:
                    rqt = request.q.qtype
                    rqd = A(str(ia))
                elif request.q.qtype == QTYPE.PTR:
                    rqt = request.q.qtype
                    rqd = PTR(str(ia.reverse_pointer))
                else:
                    rqt = QTYPE.TXT
                    rqd = TXT(f"Your request for {qt} confuses me, but here is the IP as text {str(ia)}")
            reply.add_answer(RR(qname,rqt,ttl=self.ttl,rdata=rqd))
        return reply

class DNSServer(object):

    """
        Convenience dual stack wrapper for socketserver instance allowing
        either UDP/TCP server to be started in blocking more
        or as a background thread.

        Processing is delegated to custom resolver (instance) and
        optionally custom logger (instance), handler (class), and
        server (class)

        In most cases only a custom resolver instance is required
        (and possibly logger)
    """
    def __init__(self,resolver,
                      address="",
                      port=53,
                      tcp=False,
                      logger=None,
                      handler=DNSHandler,
                      server=None,
                      ipv6=False):
        """
            resolver:   resolver instance
            address:    listen address (default: "")
            port:       listen port (default: 53)
            tcp:        UDP (false) / TCP (true) (default: False)
            logger:     logger instance (default: DNSLogger)
            handler:    handler class (default: DNSHandler)
            server:     socketserver class (default: UDPServer/TCPServer)
        """
        if not server:
            if tcp:
                server = TCPServer
            else:
                server = UDPServer
        if ipv6:
            server.address_family = socket.AF_INET6
        self.server = server((address,port),handler)
        self.server.resolver = resolver
        self.server.logger = logger or DNSLogger()

    def start(self):
        self.server.serve_forever()

    def start_thread(self):
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.server.shutdown()

    def isAlive(self):
        return self.thread.is_alive()


if __name__ == '__main__':

    import argparse,sys,time

    p = argparse.ArgumentParser(description="Shell DNS Resolver")
    p.add_argument("--map","-m",action="append",required=True,
                    metavar="<label>:<shell command>",
                    help="Map label to shell command (multiple supported)")
    p.add_argument("--origin","-o",default=".",
                    metavar="<origin>",
                    help="Origin domain label (default: .)")
    p.add_argument("--ttl","-t",default="60s",
                    metavar="<ttl>",
                    help="Response TTL (default: 60s)")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Server port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Listen address (default:all)")
    p.add_argument("--udplen","-u",type=int,default=0,
                    metavar="<udplen>",
                    help="Max UDP packet length (default:0)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP server (default: UDP only)")
    p.add_argument("--log",default="request,reply,truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix",action='store_true',default=False,
                    help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    resolver = ShellResolver(args.map,args.origin,args.ttl)
    logger = DNSLogger(args.log,args.log_prefix)

    print("Starting Shell Resolver (%s:%d) [%s]" % (
                        args.address or "*",
                        args.port,
                        "UDP/TCP" if args.tcp else "UDP"))

    for route,cmd in resolver.routes.items():
        print("    | ",route,"-->",cmd)
    print()

    ia = ip_address(args.address)


    if args.udplen:
        DNSHandler.udplen = args.udplen

    if ia.version == 6:
        udp_server = DNSServer(resolver, port=args.port, address=args.address, logger=logger, ipv6=True)
    else:
        udp_server = DNSServer(resolver, port=args.port, address=args.address, logger=logger)
    udp_server.start_thread()

    if ia.version == 6:
        tcp_server = DNSServer(resolver, port=args.port, address=args.address, tcp=True, logger=logger, ipv6=True)
    else:
        tcp_server = DNSServer(resolver, port=args.port, address=args.address, tcp=True, logger=logger)
    tcp_server.start_thread()

    while udp_server.isAlive() and tcp_server.isAlive():
        time.sleep(1)

