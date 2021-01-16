#!/usr/bin/env python
import socket
import struct
import argparse
import time
import logging
import os
import pwd
import grp
import dnslib

### Add argument parsing
parser = argparse.ArgumentParser()
parser.add_argument('-d', '--domain', required=True, help='The domain name to serve (remember trailing .) (required)')
parser.add_argument('-l', '--logfile', help='The logfile to write output to', default='dnscheck.log')
parser.add_argument('-U', '--user', help='Which user to drop privileges to after logfile open & port bind', default='nobody')
parser.add_argument('-G', '--group', help='Which group to drop privileges to after logfile open & port bind', default='nobody')
args=parser.parse_args()

### Configure logfile
if os.access(args.logfile,os.F_OK):
    ### logfile exists
    if not os.access(args.logfile,os.W_OK):
        print("Unable to write to logfile %s - bailing out" % args.logfile)
        exit(1)
else:
    ### logfile doesn't exist
    if not os.access(os.path.split(args.logfile)[0],os.W_OK):
        print("Unable to write to logfile folder %s - bailing out" % os.path.split(args.logfile)[0])
        exit(1)
logging.basicConfig(filename=args.logfile,level=logging.INFO,format='%(levelname)s:%(message)s')

### Function to output to the console with a timestamp
def output(message):
    logging.info(" [%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),message))

def output_err(message):
    logging.warning(" [%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),message))

def drop_privileges(uid_name, gid_name):
    if os.getuid() != 0:
        # Not running as root
        return

    # Get the uid/gid to drop to
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

    # Ensure a very conservative umask
    old_umask = os.umask(0o77)

class DNSQuery:
    def __init__(self, data):
        output(data)
        self.data=data
        self.qtype=None
        self.domain=''
        self.opcode = int((data[2] >> 3) & 15)                                      ### Opcode bits
        if self.opcode == 0:                                                        ### opcode 0 is a standard query
            position=12                                                             ### query begins at byte 12
            labellength=int(data[position])                                         ### Length of the first label
            while labellength != 0:                                                 ### search through data until a 0 byte is found
                self.domain+=data[position+1:position+labellength+1]+'.'            ### add this label part to self.domain
                position+=labellength+1                                             ### Move position to the beginning of the next label
                labellength=ord(str(data[position]))                                ### Find length of the next label
            self.qtype=data[position+1:position+3]                                  ### query type is the next two bytes
            self.qtype=struct.unpack(">h",self.qtype)                               ### Convert to tuple of integers
            self.qtype=self.qtype[0]                                                ### Get first element of the tuple
            output(self.qtype)

    def dnsheader(self,rcode):                                                      ### This function builds and returns a DNS header with the given rcode
        packet=b''                                                                   ### Initialize packet variable
        packet+=self.data[:2]                                                       ### Query ID (16 bits) (copied from original query)
        packet+=b'\x81'                                                              ### QR, Opcode (4 bits), AA, TC, RA
        if(rcode==5):
            packet+=b'\x85'                                                          ### RA, Z, AD, CD, Rcode refused (4 bits)
            packet+=self.data[4:6]                                                  ### QDCOUNT (16 bits) (copied from original query)
            packet+=b'\x00\x00'                                                      ### ANCOUNT (16 bits)
        elif(rcode==2):
            packet+=b'\x82'                                                          ### RA, Z, AD, CD, Rcode servfail (4 bits)
            packet+=self.data[4:6]                                                  ### QDCOUNT (16 bits) (copied from original query)
            packet+=b'\x00\x00'                                                      ### ANCOUNT (16 bits)
        else:
            packet+=b'\x80'                                                          ### Z, AD, CD, Rcode no error (4 bits)
            packet+=self.data[4:6]                                                  ### QDCOUNT (16 bits) (copied from original query)
            packet+=b'\x00\x02'                                                      ### ANCOUNT (16 bits)
        packet+=b'\x00\x00'                                                          ### NSCOUNT (16 bits)
        packet+=b'\x00\x00'                                                          ### ARCOUNT (16 bits)
        return packet

    def txtreply(self,empty=False):                                                 ### This function builds and returns a v4 RR response packet section
        packet=b''                                                                   ### Initialize packet variable
        temp=self.data.find(b'\x00',12)                                              ### Find the first 0 byte, marks the end of the question
        packet+=self.data[12:temp+5]                                                ### Original RR question (variable length) (copied from original query)
        if not empty:
            ### add first RR in answer section
            packet+=b'\xc0\x0c'                                                      ### Pointer to domain name (16 bits)
            packet+=b'\x00\x10'                                                      ### RR type (TXT record) (16 bits)
            packet+=b'\x00\x01'                                                      ### RR class (IN) (16 bits)
            packet+=b'\x00\x00\x00\x3c'                                              ### RR TTL (60 seconds) (16 bits)
            txt=b"Your DNS server IP is %s" % client[0]                              ### Put the answer string together
            packet+=b'\x00'+chr(len(txt)+1)                                          ### RR RDLENGTH
            packet+=bchr(len(txt))+txt                                               ### Answer
            if not args.ip == None:                                                 ### add second RR in answer section
                packet+=b'\xc0\x0c'                                                  ### Pointer to domain name (16 bits)
                packet+=b'\x00\x10'                                                  ### RR type (TXT record) (16 bits)
                packet+=b'\x00\x01'                                                  ### RR class (IN) (16 bits)
                packet+=b'\x00\x00\x00\x3c'                                          ### RR TTL (60 seconds) (16 bits)
                txt=args.badreply                                                   ### Default to args.badmessage
                for ip in args.ip:                                                  ### Check each IP in args.ip
                    if client[0] == ip:                                             ### Compare with client IP
                        txt=args.goodreply                                          ### Match! Return args.goodmessage
                        break                                                       ### Break out of the loop
            packet+=b'\x00'+chr(len(txt)+1)                                          ### RR RDLENGTH
            packet+=chr(len(txt))+txt                                               ### Answer
        return packet

if __name__ == '__main__':
    #try:
    #    if args.protocol=="4":
    #        udpsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            ### Create IPv4 udp socket
    #    else:
    #        udpsocket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)           ### Create IPv6 udp socket
    #    udpsocket.bind(('',53))                                                     ### and bind to port 53
    #except:
    #    output_err("Unable to create and bind UDP socket on port 53, exiting.")
    #    sys.exit()

    try:
        udpsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            ### Create IPv4 udp socket
        #udpsocket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)           ### Create IPv6 udp socket
        udpsocket.bind(('',53))                                                     ### and bind to port 53
    except:
        output_err("Unable to create and bind UDP socket on port 53, exiting.")
        sys.exit()

    output("Dropping privileges...")
    drop_privileges(uid_name=args.user,gid_name=args.group)

    output("Waiting for queries...")
    try:
        while 1:                                                                    ### loop while waiting for packets
            data, client = udpsocket.recvfrom(1024)                                 ### Receive data from socket
            servfail=False
            querypacket = dnslib.DNSRecord.parse(data)
            #output(querypacket)
            output(querypacket.header.id)

            output(querypacket.questions)
            #response = querypacket.reply()
            #response.add_answer(dnslib.RR.fromZone(f"que.sti.on 300 TXT No Response Needed for {client[0]}"))

            response = dnslib.DNSRecord(dnslib.DNSHeader(qr=1,aa=1,ra=1,id=querypacket.header.id),
                                      q=dnslib.DNSQuestion("que.sti.on"),
                                      a=dnslib.RR("que.sti.on",rdata=dnslib.A("127.0.0.1")))

            udpsocket.sendto(response.pack(),client)                                ### Respond
    except KeyboardInterrupt:
        output('Control-c received, exiting')
        udpsocket.close()
