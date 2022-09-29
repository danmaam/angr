from collections import defaultdict
from dis import Instruction
from inspect import trace
from multiprocessing.sharedctypes import Value
from sqlite3 import Timestamp
from typing import Dict, List, Optional
import collections
from copy import copy
import sys

# LAST BASE: 0x7ff6153c0000

from sympy import false, true
import angr

from angr.engines.pcode.lifter import IRSB

from .cfg_job_base import CFGJobBase
from .cfg_base import CFGBase
from ..forward_analysis import ForwardAnalysis
from ...knowledge_plugins.cfg import CFGNode, MemoryDataSort, MemoryData, IndirectJump, IndirectJumpType
from angr.analyses.forward_analysis.job_info import JobInfo
from angr.codenode import CodeNode, BasicBlock
from ...state_plugins.callstack import CallStack
from ...errors import SimEmptyCallStackError

from ..analysis import AnalysesHub
import capstone
import struct
import logging
import json
import pyvex
import archinfo

import IPython

l = logging.getLogger(name=__name__)


# TODO: TI PREGO TROVA UN MODO MIGLIORE DI FARE IL BLOCK SPLIT FA SCHIFO
lifted = {}

splitted = set()
class CFGJob():
    def __init__(self, addr: int, node: CFGNode, destination: int, block_irsb : pyvex.IRSB,
                 last_addr: Optional[int] = None,
                 src_node: Optional[CFGNode] = None, src_ins_addr: Optional[int] = None,
                 src_stmt_idx: Optional[int] = None, returning_source=None, syscall: bool = False, thread = '0'):
        self.addr = addr
        self.node = node
        self.destination = destination
        self.last_addr = last_addr
        self.src_node = src_node
        self.src_ins_addr = src_ins_addr
        self.src_stmt_idx = src_stmt_idx
        self.returning_source = returning_source
        self.syscall = syscall
        self.block_irsb = block_irsb
        self.thread = thread

        

class CFGInstrace(ForwardAnalysis, CFGBase):
    """
    The CFG is recovered from a list of executed instructions, and a trace
    of execution, one per thread
    """
    tag = 'CFGInstrace'

    class State:
        def __init__(self):
            self.function = None
            self.working = None

        def set_function(self, fun):
            self.function = fun
        
        def set_working(self, working):
            self.working = working

        def pp(self):
            print(hex(self.working.addr))

    # Load the set of instructions that shouldn't be tracked
    def load_libraries(self, x):
        with open(x, "rb") as f:
            content = f.read()
            chunks = [content[t:t + 16] for t in range(0, len(content), 16)]
            for c in chunks:
                addr = struct.unpack('<q', c[:8])[0]
                size = struct.unpack('<q', c[8:])[0]
                self.avoided_addresses[addr] = addr + size


    def __init__(self, trace, to_avoid_functions, normalize=False, base_state=None, detect_tail_calls=False, low_priority=False, model=None):
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

        self._callstack : CallStack = None

        # TODO: load also bytestrings
        with open(trace, "rb") as trace_stream:
            buf = trace_stream.read()
            self._ins_trace = json.loads(buf)
        
        self.avoided_addresses = {}
        self.load_libraries(to_avoid_functions)
        print(self.avoided_addresses)

        self.lift_cache = {}

        self._analyze()

        # shitty hacks just to test the code working
        self._low_img = 0x5616e85e4000
        self._high_img = 0x55b5326c9ab8

        

        # self.project.loader._instruction_map



    def next_irsb_block(self, tid, ts):
        
        block_head = None

        th_trace = self._ins_trace['thread_exec_trace'][tid]
    
        instructions = []

        while True:
            try:
                current_instruction = th_trace.pop(0)
            except IndexError:
                self._should_abort = True
                print("porcodio ho finito")
                return (-1,-1,-1)

            block_head = current_instruction['address'] if block_head is None else block_head
            
            instructions.append(self.project.loader._instruction_map[current_instruction['address']][ts])


            if 'destination' in current_instruction.keys():
                # end of the basic block, lift it to IRSB

                bytecode = b''.join(instructions)
                
                # check if the block is in lift cache
                if block_head in self.lift_cache.keys():
                    irsb = self.lift_cache[block_head]
                
                else: 
                    irsb = pyvex.lift(bytecode, block_head,
                                    archinfo.ArchAMD64())
                    self.lift_cache[block_head] = irsb


                next_ip = current_instruction['destination']

                lifted[block_head] = bytecode

                #FOR DEBUGGING PURPOSES
                # md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                # for i in md.disasm(bytecode, block_head):
                #     sys.stderr.write("0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str))
                # sys.stderr.write("\n")
                
                break
            

        return block_head, irsb, next_ip


    def range(self, addr):
        return self._low_img <= addr and addr <= self._high_img

    def _pre_analysis(self):
        # build basic blocks from the instruction trace
        # need to emulate the trace for each thread
        # TODO: handle self modifying code
        # TODO: add multithread support

        self._initialize_cfg()

        # TODO: process in parallel each thread
        # First try with trace at timestamp 0 and thread 0
        (block_head, irsb, next_ip) = self.next_irsb_block('0', 0)


        # Create the current function in the Function Manager
        initial = self.functions.function(
            addr=block_head, create=True)

        # Sets as none the entry point of the function
        function_entry = None     

        # create the self._current pair
        self._current = self.State()
        self._current.function = initial
        self._current.working = function_entry

        # TODO: decomment the following code
        # create in the cfg the entry for this first function

        # node = CFGNode(block_head, len(
        #     bytecode), self.model, irsb=irsb)
        # self.model.add_node(block_head, node)

        new_job = CFGJob(
            block_head, None, next_ip, block_irsb=irsb)
        self._insert_job(new_job)



    def _job_key(self, job):
        return job.addr

    def _job_queue_empty(self) -> None:
        l.debug("Job queue is empty. Stopping.")


    def _pre_job_handling(self, job: CFGJob) -> None:
        group : pyvex.IRSB = job.block_irsb
        working : BasicBlock = self._current.working

        # search for a node at the same address in the model
        node : BasicBlock = self.model.get_any_node(addr = group.addr, anyaddr = True)

        if node is not None:
            # compare the found node with the current group

            if node.addr == group.addr:
                # the node is a phantom one and must be converted to a non phantom
                if node.is_phantom:
                    l.debug(f"Converting phantom node {hex(node.addr)} to real node")
                    node.phantom_to_node(group)
                    working = node
                else:
                    # TODO: handle self modifying code at the same address location
                    while node._irsb == 'Ijk_Splitted':
                        node = node.next

                    working = node

            # jump in middle of a function

            # TODO: differentiate between jump in middle of funciton or jump not to the first instruction \
            # of a block

            # TODO: make get any node return a list of nodes and not a single node
            else:
                working = self.split_node(node, group.addr)

        else:
            # there isn't any node with the address of the current group
            # just create a new node
            l.debug(f"Creating new Basic Block for target {hex(group.addr)}")
            node = BasicBlock(group.addr, group.size, self._current.function.transition_graph, irsb=group)
            # check for the beginning of the program
            if working is not None:
                self._current.function._transit_to(working, node)
            working = node

        self._current.working = working

        assert self._current.working is not None
        return     



    def split_node(self, node, target) -> BasicBlock :
        l.debug(f"Splitting node at {hex(target)}")
        
        bytecode = lifted[node.addr]
        offset = target - node._irsb.addr

        car_bytecode = bytecode[:offset]
        cdr_bytecode = bytecode[offset:]

        # split the node
        (a, b) =  self._current.function._split_node(node, target, car_bytecode, cdr_bytecode)

        # update the lifted bytecode
        lifted[node._irsb.addr] = car_bytecode
        lifted[target] = cdr_bytecode

        self.model.remove_node(node.addr, node)
        self.model.add_node(a.addr, a)
        self.model.add_node(b.addr, b)

        splitted.add(a.addr)
        splitted.add(b.addr)

        return b
    
    def should_call_be_tracked(self, target):
        for (x,y) in self.avoided_addresses.items():
            if x <= target and target < y:
                return False
        return True

    def process_type(self, target):
        
        working : BasicBlock = self._current.working
        jumpkind = working._irsb.jumpkind


        if jumpkind == 'Ijk_Boring':
            # handles all the jumps (conditional or not) found
            jump_targets = working._irsb.constant_jump_targets.copy()
            jump_targets.add(target)

            for t in jump_targets:
                if t != target:
                    node : BasicBlock = self.model.get_any_node(t, anyaddr=True)
                    if node is not None:
                        assert isinstance(node, BasicBlock)
                        l.debug(f"Found basic block for target {hex(t)} with head {hex(node.addr)}")
                        if not node.is_phantom and node.addr != t:
                            node = self.split_node(node, t)
                    else:
                        l.debug(f"Creating phantom node for target {hex(t)}")
                        node = BasicBlock(addr = t, is_phantom = True)
                        self.model.add_node(t, node)
                    self._current.function._transit_to(working, node)                       


        
        elif jumpkind == 'Ijk_Call':
            # Check if it's a call to a library function
            return_address = working.addr + working.size
            callsite_address = working._irsb.instruction_addresses[-1]


            if self.should_call_be_tracked(target):

                # Register the call site in the current function            
                called = self.functions.function(target, create = True)

                # Try to calculate the return from the call, so that it's possible to create the phantom node
                phantom_return = BasicBlock(return_address, is_phantom = True)

                self.model.add_node(return_address, phantom_return)
                self._current.function._transit_to(working, phantom_return)
                
                self.functions._add_call_to(self._current.function.addr, working, target, \
                    phantom_return, ins_addr = callsite_address
                    )    

                l.info(hex(callsite_address) + ": Processing call to " + hex(target) + " | ret addr at " + hex(return_address))

                if self._callstack is None:
                    self._callstack = CallStack(callsite_address, target, ret_addr=return_address, current=copy(self._current))

                else:
                    self._callstack = self._callstack.call(callsite_address, target, retn_target=return_address,
                                current=copy(self._current))
                

                        
                self._current.function = called

                assert called.addr == target


                # TODO: find a better way to find the entry point of the function instead of a crap 
                # "hello code find the node in the cfg"
                self._current.working = self.model.get_node(target) 


                


            else:
                l.info("Ignoring call @" + hex(callsite_address) + " since it's to a library function")
        
        elif jumpkind == 'Ijk_Ret' and self._callstack is not None:
            # TODO: find out if the edges to be addedd are necessary 
            self._current.function._add_return_site(self._current.working)

            l.info("Returning to " + hex(target))

            try:
                returned = self._callstack

                # if (returned.ret_addr != target):
                #     IPython.embed()

                if (returned.ret_addr != target):
                    IPython.embed()
                assert returned.ret_addr == target



                self._callstack = self._callstack.ret(target)
                self._current = returned.current
                
                pass
            except SimEmptyCallStackError:
                l.warning("Stack empty")

                


        




    # TODO: handle multiple timestamps for self modifying code 
    # From the execution trace, detects and create the next IR group to be processed
    def _get_successors(self, job: CFGJob) -> List[CFGJob]:

        target = job.destination

        #TODO: don't return -1 just to end the process
        (head, irsb, next_ip) = self.next_irsb_block(job.thread, 0)
        if self.should_abort:
            return []

        # Before going into the new job, there is the need to process the type
        # of the jumpkind of the current working basic block w.r.t the head address
        # of the new basic block


        self.process_type(target)        
        new_job = CFGJob(head, None, next_ip, irsb, thread = job.thread)

        return [new_job]
        

    # it isn't necessary to implement a post job handler
    def _post_job_handling(self, job, new_jobs, successors):
        pass


    def _handle_successor(self, job: CFGJobBase, successor, successors):
        # per each successor generated, add it to the list of jobs
        return successors

    def _intra_analysis(self):
        return

    def _post_analysis(self) -> None:
        IPython.embed()


AnalysesHub.register_default('CFGInstrace', CFGInstrace)
