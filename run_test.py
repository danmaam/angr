from collections import defaultdict
import angr
import logging
import IPython
import sys
import argparse
import os



parser = argparse.ArgumentParser("Test the CFG instruction trace analysis")
parser.add_argument('-t', '--test', help = "The test to run" )
parser.add_argument('-b', '--base_address', help = 'The Base address of the binary')
parser.add_argument('-l', '--log_level', help = 'The log level')
parser.add_argument('-o', '--operating_system', help = 'The operating system')


args = parser.parse_args()

l = logging.getLogger('instrace_tests')

if not args.test:
    l.error("No test specified")
    sys.exit(1)

else:
    # check that the test exists
    if not os.path.exists(os.path.join('dumps', args.test)):  
        l.error("Test %s does not exist" % args.test)
        sys.exit(1)

if args.log_level:
    l.setLevel(args.log_level)


if args.base_address:
    base_address = int(args.base_address, 16)
else:
    l.warning("No base address specified. Proceeding with 0x0")
    base_address = 0x0


bytecode = os.path.join('dumps', args.test, 'bytecode.bin')
trace = os.path.join('dumps', args.test, 'trace.bin')
avoid = os.path.join('dumps', args.test, 'avoid.bin')

if args.operating_system == 'Linux':
    plt = os.path.join('dumps', args.test, "plt.bin")
else:
    plt = None

a = angr.project.load_trace(bytecode, 'x86_64')
b = a.analyses.CFGInstrace(trace, avoid, OS = args.operating_system, plt_dump = plt)


IPython.embed()


with open (os.path.join('dumps', args.test, 'edges.txt'), 'r') as f:   
    lines = [x.rstrip() for x in f.readlines()] 
    for x in lines:
        command, params = x.split(':')
        match command:
            case "FUNCTION":
                curr_func = b.functions.function(addr=int(params, 16) + base_address)
                assert curr_func is not None, f"{hex(int(params, 16) + base_address)} not found"
            case "CALLSITES":
                for callsite in params.split(','):
                    callsite = b.model.get_node(int(callsite, 16) + base_address)
                    assert callsite is not None
                    assert callsite.addr in curr_func._call_sites.keys(), IPython.embed()
            case "RETSITES":
                for retsite in params.split(','):
                    retsite = b.model.get_node(int(retsite, 16) + base_address)
                    assert retsite is not None
                    assert retsite in curr_func._ret_sites
            case "EDGES":
                edges = [x.split('->') for x in params.split(',')]
                for src, dst in edges:
                    
                    src_int = int(src, 0x10) + base_address
                    dst_int = int(dst, 0x10) + base_address

                    src_node = b.model.get_node(src_int)
                    dst_node = b.model.get_node(dst_int)

                    assert src_node is not None, f"Node with address {hex(src_int) + base_address} not found"
                    assert dst_node is not None, f"Node with address {hex(dst_int) + base_address} not found"


                    assert (src_node, dst_node) in curr_func.transition_graph.edges, IPython.embed()
            case "NONRETSITES":
                for retsite in params.split(','):
                    retsite = b.model.get_node(int(retsite, 16) + base_address)
                    if retsite is not None:
                        assert retsite not in curr_func._ret_sites

            

print(" === TEST PASSED === ")
                



            
