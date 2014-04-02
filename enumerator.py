#!/usr/bin/python -tt
# -*- coding: utf-8 -*-

# Copyright (c) 2014, Milbot
<<<<<<< HEAD
# https://github.com/milbot/enumerator
#
# The MIT License (MIT)
# 
# Copyright (c) 2014 Nathan Bird
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
=======
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#   Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
#   Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
#   Neither the name of AverageSecurityGuy nor the names of its contributors may
#   be used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.
>>>>>>> ac915f713f7166689ea5e7dc9186e938bb87c4ca

import os
import sys
import subprocess
import re
import optparse
import dns.name
import dns.query
import dns.resolver

#-----------------------------------------------------------------------------
# TODO: Add description here
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
# Compiled Regular Expressions
#-----------------------------------------------------------------------------
report_re = re.compile('Nmap scan report for (.*)')
gnmap_re = re.compile('Host: (.*)Ports:')
version_re = re.compile('# Nmap 6.25 scan initiated')
host_re = re.compile('Host: (.*) .*Ports:')
ports_re = re.compile('Ports: (.*)\sIgnored State:')
os_re = re.compile('OS: (.*)\sSeq Index:')

#-----------------------------------------------------------------------------
# Functions
#-----------------------------------------------------------------------------
def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

def get_authoritative_nameserver(domain, log=lambda msg: None):
    n = dns.name.from_text(domain)

    depth = 2
    default = dns.resolver.get_default_resolver()
    nameserver = default.nameservers[0]

    last = False
    while not last:
        s = n.split(depth)

        last = s[0].to_unicode() == u'@'
        sub = s[1]

        log('Looking up %s on %s' % (sub, nameserver))
        query = dns.message.make_query(sub, dns.rdatatype.NS)
        response = dns.query.udp(query, nameserver)

        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            if rcode == dns.rcode.NXDOMAIN:
                raise Exception('%s does not exist.' % sub)
            else:
                raise Exception('Error %s' % dns.rcode.to_text(rcode))

        rrset = None
        if len(response.authority) > 0:
            rrset = response.authority[0]
        else:
            rrset = response.answer[0]

        rr = rrset[0]
        if rr.rdtype == dns.rdatatype.SOA:
            log('Same server is authoritative for %s' % sub)
        else:
            authority = rr.target
            log('%s is authoritative for %s' % (authority, sub))
            nameserver = default.query(authority).rrset[0].to_text()

        depth += 1

    return nameserver

def run_command(cmd):
    p = subprocess.Popen(cmd.split(), stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    resp = p.stdout.read()
    warnings = p.stderr.read()
    p.stdout.close()
    p.stderr.close()

    # Return any warnings and the raw response.
    return warnings, resp

def print_warnings(warnings):
    for w in warnings.split('\n'):
        if w == '':
            continue
        print '[-] {0}'.format(w)
        if w == 'QUITTING!':
            sys.exit()

def save_targets(file_name, ips):
    print '[*] Saving live target to {0}'.format(file_name)

    out = open(file_name, 'w')
    out.write('\n'.join(ips))
    out.close()


def parse_ports(port_str, broken=False):
    '''
    The 6.25 version of Nmap broke the port format by dropping a field. If
    broken is True then assume we have 6.25 output otherwise do not.
    '''
    ports = []
    for port in port_str.split(','):
        if broken == True:
            num, stat, proto, x, sn, serv, y = port.split('/')
        else:
            num, stat, proto, x, sn, y, serv, z = port.split('/')

        if serv == '':
            service = sn
        else:
            service = serv

        s = '{0}/{1} ({2}) - {3}'.format(proto, num.strip(), stat, service)
        ports.append(s)

    return ports


def parse_gnmap(file_name):
    hosts = {}
    broken = False
    gnmap = open('{0}.gnmap'.format(file_name), 'r')
    for line in gnmap:
        m = version_re.search(line)
        if m is not None:
            broken = True

        m = gnmap_re.search(line)
        if m is not None:
            # Get Hostname
            h = host_re.search(line)
            if h is None:
                host = 'Unknown'
            else:
                host = h.group(1)

            # Get Ports
            p = ports_re.search(line)
            if p is not None:
                ports = parse_ports(p.group(1), broken)
            else:
                ports = ''

            # Get OS
            o = os_re.search(line)
            if o is None:
                os = 'Unknown'
            else:
                os = o.group(1)

            hosts[host] = {'os': os,
                           'ports': ports}

    gnmap.close()

    return hosts

#-----------------------------------------------------------------------------
# Menu
#-----------------------------------------------------------------------------
def menu(target):
    menu = True
    while menu:
        print ("""
        Enumerator - Automate enumeration of your target as quickly as possible...
        Version: v0.1
        Written By: Nathan Bird (milbot)
        http://nathanbird.id.au
        
        1. Discover alive machines
            Range: %s
        2. Identify name servers
        3. Attempt zone transfer/s
        4. Low Hanging Fruit
        5. Full TCP Scan
            \x1B[3mUses unicornscan to identify open ports first\x1B[23m
        6. Full UDP Scan
            \x1B[3mUses unicornscan to identify open ports first\x1B[23m
        
        """) % ( target )
        
        menu=raw_input("What would you like to do? ") 
        if menu == "1":
            alive(target)
        elif menu == "2":
            name_servers(target)
        elif menu == "3":
            zone_transfer(target)
        elif menu == "4":
            lowfruit(target)
        elif menu == "5":
            fulltcp(target)
        elif menu == "6":
            fulludp(target)

#-----------------------------------------------------------------------------
# Discover alive machines
#-----------------------------------------------------------------------------
def alive(target):
    #
    # Setup Filenames
    #
    ping_fname = '{0}_ping_scan'.format(target.replace('/', '.'))
    target_fname = '{0}_alivetargets.txt'.format(target.replace('/', '.'))

    #
    # Run discovery scans against the address range
    #
    print '[*] Running discovery scan against targets {0}'.format(target)
    cmd = 'nmap -sn -PE -n -oA {0} {1}'.format(ping_fname, target)
    warnings, resp = run_command(cmd)
    print_warnings(warnings)

    ips = report_re.findall(resp)
    print '[+] Found {0} live targets'.format(len(ips))

    if len(ips) == 0:
        print '[-] No targets to scan. Quitting.'
        sys.exit()

    save_targets(target_fname, ips)
    print '[*] Ping scan complete\n'

#-----------------------------------------------------------------------------
# Get Name Servers
#-----------------------------------------------------------------------------
def name_servers(target):
    target_fname = '{0}_alivetargets.txt'.format(target.replace('/', '.'))
    dns_fname = '{0}_dns_scan'.format(target.replace('/', '.'))

    #
    # Run DNS discovery scans against the address range
    #
    print '[*] Running discovery scan against targets {0}'.format(target)
    cmd = 'nmap -n -oA {0} -p 53 --open -iL {1}'.format(dns_fname, target_fname)
    warnings, resp = run_command(cmd)
    print_warnings(warnings)

    ips = report_re.findall(resp)
    print '[+] Found {0} likely DNS targets'.format(len(ips))

    hosts = parse_gnmap(dns_fname)
    for host in hosts:
        print '      {0}'.format(host) 

    if len(ips) == 0:
        print '[-] No targets to scan. Quitting.'
        sys.exit()

    print '[*] DNS sweep complete\n'

#-----------------------------------------------------------------------------
# Zone Transfer(s)
#---------------------------------------------------------------------------
def zone_transfer(target):
    dns_fname = '{0}_dns_scan'.format(target.replace('/', '.'))

    hosts = parse_gnmap(dns_fname)
    for host in hosts:
        print '[+] Attempting domain identification against against {0}'.format(host)
        warnings, resp = run_command('host {0} {0}'.format(host))
        print resp

    domain = raw_input("What domain would you like to transfer? ")
    for host in hosts:
        warning, resp = run_command('dnsrecon -a -d {0} -n {1} --xml {0}.xml --csv {0}.csv'.format(domain,host))
        print resp

#-----------------------------------------------------------------------------
# Low Hanging Fruit
#-----------------------------------------------------------------------------
def lowfruit(target):
    #
    # Setup Filenames
    #
    target_fname = '{0}_alivetargets.txt'.format(target.replace('/', '.'))
    low_hanging_fruit_fname = '{0}_low_hanging_fruit'.format(target.replace('/', '.'))

    #
    # Run full scans against each IP address.
    #
    print '[*] Running full TCP scan on live addresses'
    cmd = 'cat ip_addresses_alive.txt | parallel -j2 "nmap -vv -T4 -F -O -Pn -sV --script=ftp-anon --script=http-default-accounts {} -oA low_hanging_fruit_{} && echo \'[+]     Completed NMAP Low Hanging Fruit: {}\'"'
    #cmd = 'nmap -sS -n -A --open -v '
    #cmd += '-oA {0} -iL {1}'.format(tcp_fname, target_fname)
    warnings, resp = run_command(cmd)
    print_warnings(warnings)
    print '[*]   Full scan complete.\n'

#-----------------------------------------------------------------------------
# Run TCP Scans
#-----------------------------------------------------------------------------
def fulltcp(target):
    #
    # Setup Filenames
    #
    target_fname = '{0}_alivetargets.txt'.format(target.replace('/', '.'))
    tcp_fname = '{0}_tcp_scan'.format(target.replace('/', '.'))

    #
    # Run full scans against each IP address.
    #
    print '[*] Running full TCP scan on live addresses'
    cmd = 'nmap -sS -n -A --open -v '
    cmd += '-oA {0} -iL {1}'.format(tcp_fname, target_fname)
    warnings, resp = run_command(cmd)
    print_warnings(warnings)
    print '[*]   Full scan complete.\n'

#-----------------------------------------------------------------------------
# Run UDP Scans
#-----------------------------------------------------------------------------
def fulludp(target):
    #
    # Setup Filenames
    #
    target_fname = '{0}_alivetargets.txt'.format(target.replace('/', '.'))
    udp_fname = '{0}_udp_scan'.format(target.replace('/', '.'))

    #
    # Run full scans against each IP address.
    #
    print '[*] Running full UDP scan on live addresses'
    cmd = 'nmap -sU -n -A --open -v '
    cmd += '-oA {0} -iL {1}'.format(udp_fname, target_fname)
    warnings, resp = run_command(cmd)
    print_warnings(warnings)
    print '[*]   Full scan complete.\n'

def outputmd():
    #
    # Parse full scan results and write them to a file.
    #
    print '[*] Parsing Scan results.'
    hosts = parse_gnmap(tcp_fname)
    hosts += parse_gnmap(udp_fname)

    print '[*] Saving results to {0}'.format(result_fname)
    out = open(result_fname, 'w')
    for host in hosts:
        out.write(host + '\n')
        out.write('=' * len(host) + '\n\n')
        out.write('OS\n')
        out.write('--\n')
        out.write(hosts[host]['os'] + '\n\n')
        out.write('Ports\n')
        out.write('-----\n')
        out.write('\n'.join(hosts[host]['ports']))
        out.write('\n\n\n')

    out.close()
    print '[*] Parsing results is complete.'

#-----------------------------------------------------------------------------
# Main Program
#-----------------------------------------------------------------------------
def main():

    #
    # Parse command line options
    #
    parser = optparse.OptionParser("%prog -t <target ip range> -c <client name> [-p <port range>] [-h/--help]")
    parser.add_option("-t", dest="target", type="string", help="Target IP address range, e.g. 192.168.11.200-254")
    parser.add_option("-c", dest="client", type="string", help="Client name for output file and folder structure")
    parser.add_option("-p", dest="other_ports", type="string", help="Additional target port(s) separated by comma. Note: the following default ports are included in all scans, regardless of the input to this flag: 21, 22, 23, 25, 53, 80, 110, 119, 143, 443, 135, 139, 445, 593, 1352, 1433, 1498, 1521, 3306, 5432, 389, 1494, 1723, 2049, 2598, 3389, 5631, 5800,5900, and 6000")
    (options, args) = parser.parse_args()
    target = options.target
    client = options.client
    if (options.other_ports != None):
        other_ports = str(options.targetPorts).split(",")
        
        ports = '21,22,23,25,53,80,110,119,143,443,135,139,445,593,1352,1433,1498,'
        ports += '1521,3306,5432,389,1494,1723,2049,2598,3389,5631,5800,5900,6000'
        ports += ',' + other_ports
    
    if (target == None) | (client == None):
        print parser.usage
        exit(0)

    #
    # Setup global variables
    #
    # ping_fname = '{0}_ping_scan'.format(target.replace('/', '.'))
    # target_fname = '{0}_alivetargets.txt'.format(target.replace('/', '.'))
    # syn_fname = '{0}_syn_scan'.format(target.replace('/', '.'))
    # result_fname = '{0}_results.md'.format(target.replace('/', '.'))

    #
    # Load Menu
    #
    menu(target)
    
#-----------------------------------------------------------------------------
# Start
#-----------------------------------------------------------------------------

if __name__ == "__main__": main()
