import iptc
from prometheus_client import start_http_server, Gauge

CHAIN_TOTAL = Gauge('chain_bytes_total', 'Total bytes reach chain',['table', 'chain'])
CHAIN_PACKET = Gauge('chain_packet', 'Total packet reach chain', ['table', 'chain'])

RULE_TOTAL = Gauge('rule_bytes_total', 'Total bytes reach the rule', ['table', 'chain', 'rule'])
RULE_PACKET = Gauge('rule_packet_total', 'Total packets reach the rule', ['table', 'chain', 'rule'])

RULE_COUNT = Gauge('rule_of_chain_total', 'Total rule of chain', ['table', 'chain']) 

def chainInfo(table, chain_name, RULE_TOTAL, RULE_PACKET):
    chain = iptc.Chain(table, chain_name)
    packet, byte = chain.get_counters()
    #print chain.name, 
    #print chain_packet, chain_bytes, "bytes"
    
    if len(chain.rules) > 0: 
        for rule in chain.rules:
            rpacket, rbytes, rinfo = ruleInfo(rule)
            RULE_TOTAL.labels(table.name,chain.name, rinfo).set(rbytes)
            RULE_PACKET.labels(table.name,chain.name, rinfo).set(rpacket)
    #else:
     #   RULE_TOTAL.labels(table.name,chain.name, 'no_rule').set(0)
     #   RULE_PACKET.labels(table.name,chain.name, 'no_rule').set(0)
    return packet, byte

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

    rule_info = "rule: " +  "proto: " + protocol + " src: " + src + " dst: " + \
        dst + " " +  in_interface + " " +out_interface
    #check if match None
    if(rule.matches): 
        rule_info +=  " Matches: "
        for match in rule.matches:
            rule_info += match.name + " "

    rule_info += "-j " 
    rule_info += rule.target.name 
    # get packet, bytes reach the rules 
    rule_packet, rule_bytes = rule.get_counters()
    #print rule_packet, rule_bytes , "bytes"
    return rule_packet, rule_bytes, rule_info


if __name__ == "__main__":
    start_http_server(9103)
    table = iptc.Table(iptc.Table.FILTER)
    print "Exporter is running in port 9103..."
    while True:
        for chain in table.chains:
            packet, byte = chainInfo(table, chain.name, RULE_TOTAL, RULE_PACKET)
            RULE_COUNT.labels(table.name, chain.name).set(len(chain.rules))
            CHAIN_PACKET.labels(table.name, chain.name).set(packet)
            CHAIN_TOTAL.labels(table.name, chain.name).set(byte)
