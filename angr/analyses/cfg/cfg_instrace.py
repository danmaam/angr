from collections import defaultdict
from dis import Instruction
from inspect import trace
from sqlite3 import Timestamp
from typing import Dict, List, Optional
import collections

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

        self._callstack : CallStack = None

        # TODO: load also bytestrings
        with open(trace, "rb") as trace_stream:
            buf = trace_stream.read()
            self._ins_trace = json.loads(buf)

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
            current_instruction = th_trace.pop(0)
            block_head = current_instruction['address'] if block_head is None else block_head

            instructions.append(self.project.loader._instruction_map[current_instruction['address']][ts])


            if 'destination' in current_instruction.keys():
                # end of the basic block, lift it to IRSB

                bytecode = b''.join(instructions)
                
                irsb = pyvex.lift(bytecode, block_head,
                                  archinfo.ArchAMD64())

                next_ip = current_instruction['destination']

                # FOR DEBUGGING PURPOSES
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                for i in md.disasm(bytecode, block_head):
                    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                print("\n")
                
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


    def split_irsb(self, irsb, split_addr):
        # assert the address of splitting is in range of the irsb
        assert irsb.addr < split_addr and split_addr <= irsb.addr + irsb.size

        #find the split point
        split_idx = [idx for (idx, elem) in enumerate(irsb.statements) if hasattr(elem, 'addr') and elem.addr == split_addr][0]

        (car, cdr) = (irsb.statements[:split_idx], irsb.statements[split_idx:])

        # create the irsbs
        car_irsb = irsb.empty_block(archinfo.ArchAMD64(), irsb.addr, car)
        cdr_irsb = irsb.empty_block(archinfo.ArchAMD64(), split_addr, cdr, jumpkind = irsb.jumpkind)

        # create the new basic blocks
        car_bb = BasicBlock(car_irsb.addr, car_irsb.size, self._current.function.transition_graph, irsb=car_irsb)
        cdr_bb = BasicBlock(cdr_irsb.addr, cdr_irsb.size, self._current.function.transition_graph, irsb=cdr_irsb)

        return (car_bb, cdr_bb)

    def _job_key(self, job):
        return job.addr

    def _job_queue_empty(self) -> None:
        l.info("Job queue is empty. Stopping.")


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
                    node.phantom_to_node(self._current.function.transition_graph, group)
                    working = node
                else:
                    # TODO: handle self modifying code at the same address location
                    assert node._irsb == group

            # jump in middle of a function
            # TODO: differentiate between jump in middle of funciton or jump not to the first instruction \
            # of a block


            # TODO: make get any node return a list of nodes and not a single node
            else:
                working = self.split_node(node, group)

        else:
            # there isn't any node with the address of the current group
            # just create a new node
            node = BasicBlock(group.addr, group.size, self._current.function.transition_graph, irsb=group)
            # check for the beginning of the program
            if working is not None:
                self._current.function._transit_to(working, node)
            working = node

        self._current.working = working

        return     



    def split_node(self, node, target) -> BasicBlock :
        (a, b) = self.split_irsb(node._irsb, target)
        self.model.remove_node(node.addr, node)
        self.model.add_node(a.addr, a)
        self.model.add_node(b.addr, b)
        return b
        

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
                        if not node.is_phantom and node.addr != t:
                            node = self.split_node(node, t)
                    else:
                        node = BasicBlock(addr = t, is_phantom = True)
                        self.model.add_node(t, node)
                    self._current.function._transit_to(working, node)                       


        
        elif jumpkind == 'Ijk_Call':
            # Check if it's a call to a library function
            return_address = working.addr + working.size
            # TODO: for the future myself: you don't want to find the address of call by accessing to the last address, 
            # trust me, you don't want to do that, you will regret of this piece of code you wrote
            callsite_address = working._irsb.instruction_addresses[-1]


            # TODO: dump from pin API call instead of this horrible check 
            if target != return_address:
                # Register the call site in the current function            
                called = self.functions.function(target, create = True)

                # Try to calculate the return from the call, so that it's possible to create the phantom node
                phantom_return = BasicBlock(return_address, is_phantom = True)

                self.model.add_node(return_address, phantom_return)
                self._current.function._transit_to(working, phantom_return)
                
                self.functions._add_call_to(self._current.function.addr, working, target, \
                    phantom_return, ins_addr = callsite_address
                    )           

                if self._callstack is None:
                    self._callstack = CallStack(callsite_address, target, ret_addr=return_address, current=self._current)

                else:
                    self._callstack = self._callstack.call(callsite_address, target, retn_target=return_address,
                                current=self._current)

                        
                self._current.set_function(called)
                # TODO: find a better way to find the entry point of the function instead of a crap 
                # "hello code find the node in the cfg"
                self._current.working = self.model.get_node(target)

                l.info(hex(callsite_address) + ": Processing call to " + hex(target) + " | ret addr at " + hex(return_address))

            else:
                l.warning("Ignoring call @" + hex(callsite_address) + " since it's to a library function")
        
        elif jumpkind == 'Ijk_Ret' and self._callstack is not None:
            # TODO: find out if the edges to be addedd are necessary 
            l.info("Returning to " + hex(target))
            #7working.pp()
            try:
                returned = self._callstack
                self._callstack = self._callstack.ret(target)
                self._current = returned.current
                
                pass
            except SimEmptyCallStackError:
                l.warning("Stack empty")
            except AttributeError:
                IPython.embed()


        




    # TODO: handle multiple timestamps for self modifying code 
    # From the execution trace, detects and create the next IR group to be processed
    def _get_successors(self, job: CFGJob) -> List[CFGJob]:

        (head, irsb, next_ip) = self.next_irsb_block(job.thread, 0)

        # Before going into the new job, there is the need to process the type
        # of the jumpkind of the current working basic block w.r.t the head address
        # of the new basic block

        self.process_type(head)        
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


AnalysesHub.register_default('CFGInstrace', CFGInstrace)
