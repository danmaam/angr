from collections import defaultdict
from dis import Instruction
from inspect import trace
from sqlite3 import Timestamp
from typing import Dict, Optional
from .cfg_base import CFGBase
from ..forward_analysis import ForwardAnalysis
from ...knowledge_plugins.cfg import CFGNode, MemoryDataSort, MemoryData, IndirectJump, IndirectJumpType

from ..analysis import AnalysesHub
import capstone
import struct
import logging
import json
import pyvex
import archinfo

l = logging.getLogger(name=__name__)
class CFGInstrace(ForwardAnalysis, CFGBase):
    """
    The CFG is recovered from a list of executed instructions, and a trace
    of execution, one per thread
    """
    tag = 'CFGInstrace'

    def __init__(self, trace, normalize=False, base_state=None, detect_tail_calls=False, low_priority=False, model=None):
        ForwardAnalysis.__init__(self, allow_merging=False)
        CFGBase.__init__(
            self,
            'instrace',
            0,
            normalize=normalize,
            force_segment=False,
            base_state=base_state,
            resolve_indirect_jumps=False,
            indirect_jump_resolvers=None,
            indirect_jump_target_limit=100000,
            detect_tail_calls=detect_tail_calls,
            skip_unmapped_addrs=True,
            low_priority=low_priority,
            model=model,
        )

        #TODO: load also bytestrings
        with open(trace, "rb") as trace_stream:
            buf = trace_stream.read()
            self._ins_trace = json.loads(buf)

        self._analyze()
        
        # shitty hacks just to test the code working
        self._low_img = 0x55b5326c7000
        self._high_img = 0x55b5326c9ab8




        #self.project.loader._instruction_map


    def range(self, addr):
        return self._low_img <= addr and addr <= self._high_img
    
    def _pre_analysis(self):
        # build basic blocks from the instruction trace
        # need to emulate the trace for each thread
        # TODO: handle self modifying code

        self._initialize_cfg()

        print(self._model)

        first = None
        second = None

        Jobs = dict() #dictionary of Jobs to be processed
        for tid in self._ins_trace['thread_exec_trace'].keys():
            # reset the start of the current basic block
            basic_block_begin = None
            for trace in self._ins_trace['thread_exec_trace'][tid]:
                if not basic_block_begin:
                    basic_block_begin = trace['address']
                    current_bytecode = b""
                current_bytecode += self.project.loader._instruction_map[trace['address']][trace['timestamp']]
                # we arrived at the end of a basic block 
                if 'destination' in trace.keys():
                    irsb = pyvex.lift(current_bytecode, basic_block_begin, archinfo.ArchAMD64())
                    print(basic_block_begin)
                    node = CFGNode(basic_block_begin, len(current_bytecode), self.model, irsb=irsb)     
                    basic_block_begin = None

                    #HACK TO TRY THINGS
                    if first is None:
                        first = node
                    elif second is None:
                        second = node

                    self._model.add_node(node.block_id, node)

        #try to add nodes to the CFG
        print(self.graph)
        self.graph.add_edge(first, second)

        print("barusso", self._model.get_predecessors(first))
           


        
class CFGJob:
    def __init__(self, addr: int, func_addr: int, jumpkind: str, timestamp: int,
                 ret_target: Optional[int]=None, last_addr: Optional[int]=None,
                 src_node: Optional[CFGNode]=None, src_ins_addr:Optional[int]=None,
                 src_stmt_idx: Optional[int]=None, returning_source=None, syscall: bool=False):
        self.addr = addr
        self.func_addr = func_addr
        self.jumpkind = jumpkind
        self.timestamp = timestamp
        self.ret_target = ret_target
        self.last_addr = last_addr
        self.src_node = src_node
        self.src_ins_addr = src_ins_addr
        self.src_stmt_idx = src_stmt_idx
        self.returning_source = returning_source
        self.syscall = syscall

    



        


AnalysesHub.register_default('CFGInstrace', CFGInstrace)