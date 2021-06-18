# -*- encoding: utf-8 -*-
# requires a recent enough python with idna support in socket
# pyopenssl, cryptography and idna

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna
import sys
import argparse
from datetime import datetime

from socket import socket
from collections import namedtuple

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')

HOSTS = [    
    ('expired.badssl.com', 443),
    ('wrong.host.badssl.com', 443),
    ('soa-crm.munich-airport.de', 443),
]

def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer

def get_certificate(hostname, port=443):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_valid_end(cert):
    try:
        diff_date = cert.not_valid_after - datetime.now()
        return '''\tlonger than 60 days: {over60d}
    \tunder 60 days: {under60d}
    \tunder 45 days: {under45d}
    \tdays left {under30d}'''.format(
            over60d=diff_date.days > 60, under60d=diff_date.days < 60,
            under45d=diff_date.days < 45, under30d='more than 30' if diff_date.days > 30 else diff_date.days )
    except x509.ExtensionNotFound:
        return 'valid end not available'


def print_basic_info(hostinfo, noIP=False):
    peername = '' if noIP else '… {hostinfo.peername}'
    s = '''» {hostname} « {peername}
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter}
    '''.format(
            hostname=hostinfo.hostname,
            peername=peername,
            commonname=get_common_name(hostinfo.cert),
            SAN=get_alt_names(hostinfo.cert),
            issuer=get_issuer(hostinfo.cert),
            notbefore=hostinfo.cert.not_valid_before,
            notafter=hostinfo.cert.not_valid_after
    )
    print(s)

def check_it_out(hostname, port=443, noIP=False):
    hostinfo = get_certificate(hostname, port)
    print_basic_info(hostinfo, noIP)
    print(get_valid_end(hostinfo.cert))
    #for attr in dir(hostinfo.cert):
    #    print("hostinfo.cert.%s = %r" % (attr, getattr(hostinfo.cert, attr)))

def main(argv):
    
    parser = argparse.ArgumentParser(
        description='Helper for checking SSL-Certificates.')
    parser.add_argument('-n', '--name', help='name of the host to check')
    parser.add_argument('-no-ip', help='don\'t show the ip of the host', action='store_true')
    parser.add_argument('-a', '--all', help='check list of host from the file', action='store_true')

    args = parser.parse_args()
    #print(args)
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()
    
    if args.all:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
            for hostinfo in e.map(lambda x: get_certificate(x[0], x[1]), HOSTS):
                print_basic_info(hostinfo)
    if args.name:
        check_it_out(args.name, noIP=args.no_ip)

if __name__ == "__main__":
    main(sys.argv[1:])