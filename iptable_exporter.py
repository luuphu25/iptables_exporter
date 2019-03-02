import time, sys
from prometheus_client import start_http_server, Counter
import iptc
table = iptc.Table(iptc.Table.FILTER)
chain = iptc.Chain(table, 'INPUT')
forward_chain = iptc.Chain(table, 'FORWARD')
output_chain = iptc.Chain(table, 'OUTPUT')
for chain in table.chains:
    for rule in chain.rules:
        for match in rule.matches:
                (input_packets, input_bytes) = rule.get_counters()
                print input_packets, input_bytes
""" for rule in forward_chain.rules:
    (forward_packets, forward_bytes) = rule.get_counters()

for rule in output_chain.rules:
    (output_packets, output_bytes) = rule.get_counters()
print(output_chain.get_counters())
print "Total rules per chain: "
print ("input: ", len(input_chain.rules))
print ("forward: ", len(forward_chain.rules))
print ("output: ", len(output_chain.rules))

print "Total packet per chain: "
print ("input: ", input_packets)
print ("forward: ", forward_packets)
print ("output: ", output_packets)

print "Total bytes per chain: "
print ("input: ", input_bytes)
print ("forward: ", forward_bytes)
print ("output: ", output_bytes) """

#while True:
#    for rule in chain.rules:
#        (packets, bytes) = rule.get_counters()
#        print packets, bytes, "bytes"
#    sys.stdout.flush()
#    time.sleep(3)
#    table.refresh()