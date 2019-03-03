import iptc
from prometheus_client import start_http_server, Gauge
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
RULE_TOTAL = Gauge('chain_bytes_total', 'Total bytes reach chain',['chain'])
RULE_PACKET = Gauge('chain_packet', 'Total packet reach chain', ['chain'])


def chainInfo(table, chain):
    chain = iptc.Chain(table, chain)
    chain_packet, chain_bytes = chain.get_counters()
    print chain.name, 
    print chain_packet, chain_bytes, "bytes"
    
    if len(chain.rules) > 0: 
        for rule in chain.rules:
            ruleInfo(rule)
    else:
        print "0"
    return chain_packet, chain_bytes

def ruleInfo(rule):
    #get rule syntax 
    protocol = rule.protocol
    src = rule.src
    dst = rule.dst
    #check if in, out is None (not config)
    if (rule.in_interface!=None):
        in_interface = "in: " + rule.in_interface
    else: 
        in_interface = ""

    if (rule.out_interface!=None):
        out_interface = "out: " + rule.out_interface
    else: 
        out_interface = ""

    print "rule", "proto:", protocol, "src:", src, "dst:", \
        dst, in_interface, out_interface,
    #check if match None
    if(rule.matches): 
        print "Matches:",
        for match in rule.matches:
            print match.name,

    print "-j ", rule.target.name
    # get packet, bytes reach the rules 
    rule_packet, rule_bytes = rule.get_counters()
    #print rule_packet, rule_bytes , "bytes"



class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        #table = iptc.Table(iptc.Table.FILTER)
        #packet, byte = chainInfo(table, "INPUT")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Hello World")


if __name__ == "__main__":
    start_http_server(8000)
    while True:
        table = iptc.Table(iptc.Table.FILTER)
        packet, byte = chainInfo(table, "INPUT")
        RULE_PACKET.labels('INPUT').set(packet)
        RULE_TOTAL.labels('INPUT').set(byte)
#    server = HTTPServer(('localhost', 8001), MyHandler)
#    server.serve_forever()

""" if __name__ == '__main__':
    httpd = make_server('', 8000, my_app)
    httpd.serve_forever()

    while True:
        start_http_server(8000)   
        table = iptc.Table(iptc.Table.FILTER)
        packet, byte = chainInfo(table, "INPUT")
        rule_packet.set(packet)
        rule_bytes.set(byte) """