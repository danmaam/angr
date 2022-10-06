import angr
import logging
import IPython
import sys
logging.getLogger('angr').setLevel('INFO')

if len(sys.argv) < 2:
    print('Usage: test.py <Base Address>')
    sys.exit(1)

a = angr.project.load_trace('./bytecode.bin', 'x86_64')
b = a.analyses.CFGInstrace('./trace.json', './avoid.bin')

base_address = int(sys.argv[1], 16)

# tests to run 
funcs = {}
funcs[0x1190] = {}

funcs[0x1190][0x1190] = [0x119F, 0x11AD]
funcs[0x1190][0x119F] = [0x11AB]
funcs[0x1190][0x11AB] = [0x11B9]
funcs[0x1190][0x11AD] = [0x11B9]

funcs[0x1150] = {}
funcs[0x1150][0x1150] = [0x115F, 0x116D]
funcs[0x1150][0x115F] = [0x116B]
funcs[0x1150][0x116B] = [0x1179]
funcs[0x1150][0x116D] = [0x1179]



for func, edges in funcs.items():
    function = b.functions.function(addr=base_address + func)
    assert function is not None
    for src, dsts in edges.items():
        src_node = b.model.get_node(base_address + src)
        assert src_node is not None
        for dst in dsts:
            dst_node = b.model.get_node(base_address + dst)
            assert dst_node is not None
            assert function.transition_graph.has_edge(src_node, dst_node), IPython.embed()

            