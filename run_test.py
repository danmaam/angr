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


funcs = {}
with open (os.path.join('dumps', args.test, 'edges.txt'), 'r') as f:
    lines = [x.rstrip() for x in f.readlines()]
    for l in lines:
        func_addr, edges = l.split(':')

        func_addr = int(func_addr, 16)
        funcs[func_addr] = defaultdict(lambda: [])

        for e in edges.split('|'):
            src, dsts = e.split('->')
            src = int(src, 16)
            for d in dsts.split(';'):
                dst = int(d, 16)
                funcs[func_addr][src].append(dst)

print(funcs)

bytecode = os.path.join('dumps', args.test, 'bytecode.bin')
trace = os.path.join('dumps', args.test, 'trace.json')
avoid = os.path.join('dumps', args.test, 'avoid.bin')

if args.operating_system == 'Linux':
    plt = os.path.join('dumps', args.test, "plt.bin")
else:
    plt = None

a = angr.project.load_trace(bytecode, 'x86_64')
b = a.analyses.CFGInstrace(trace, avoid, OS = args.operating_system, plt_dump = plt)


for func, edges in funcs.items():
    function = b.functions.function(addr=base_address + func)
    assert function is not None
    for src, dsts in edges.items():
        src_node = b.model.get_node(base_address + src)
        assert src_node is not None
        for dst in dsts:
            dst_node = b.model.get_node(base_address + dst)
            assert dst_node is not None
            assert function.transition_graph.has_edge(src_node, dst_node)

print(" === TEST PASSED === ")

            
