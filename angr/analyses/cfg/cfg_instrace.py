from collections import defaultdict
from dis import Instruction
from inspect import trace
from sqlite3 import Timestamp
from typing import Dict, List, Optional

from sympy import false, true

from angr.engines.pcode.lifter import IRSB

from .cfg_job_base import CFGJobBase
from .cfg_base import CFGBase
from ..forward_analysis import ForwardAnalysis
from ...knowledge_plugins.cfg import CFGNode, MemoryDataSort, MemoryData, IndirectJump, IndirectJumpType
from angr.analyses.forward_analysis.job_info import JobInfo
from angr.codenode import CodeNode, BasicBlock


from ..analysis import AnalysesHub
import capstone
import struct
import logging
import json
import pyvex
import archinfo

import IPython

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

        self._state = {}

        # TODO: load also bytestrings
        with open(trace, "rb") as trace_stream:
            buf = trace_stream.read()
            self._ins_trace = json.loads(buf)

        self._analyze()

        # shitty hacks just to test the code working
        self._low_img = 0x55b5326c7000
        self._high_img = 0x55b5326c9ab8

        # self.project.loader._instruction_map

    def range(self, addr):
        return self._low_img <= addr and addr <= self._high_img

    def _pre_analysis(self):
        # build basic blocks from the instruction trace
        # need to emulate the trace for each thread
        # TODO: handle self modifying code
        # TODO: update the method to insert just the first job per each thread
        # TODO: add multithread support

        self._initialize_cfg()

        # try with first thread
        tid = '0'
        ts = 0

        th_trace = self._ins_trace['thread_exec_trace'][tid]

        block_head = None
        bytecode = b""

        instructions = []
        instruction_info = []

        # build the irsb of the group

        while True:
            current_instruction = th_trace.pop(0)
            block_head = current_instruction['address'] if block_head is None else block_head

            instructions.append(self.project.loader._instruction_map[current_instruction['address']][ts])


            if 'destination' in current_instruction.keys():
                # end of the basic block, lift it to IRSB

                bytecode = b''.join(instructions)
                
                irsb = pyvex.lift(bytecode, block_head,
                                  archinfo.ArchAMD64())


                # create the first function in the function manager
                initial = self.functions.function(
                    addr=block_head, create=True)


                # create the entry basic block
                first_block = BasicBlock(
                    block_head, graph=initial.transition_graph)


                # create the self._current pair
                self._current = {}
                self._current['function'] = initial
                self._current['working'] = first_block

                # create in the cfg the entry for this first function
                node = CFGNode(block_head, len(
                    bytecode), self.model, irsb=irsb)

                self.model.add_node(block_head, first_block)
                self.model.add_node(block_head, node)

                new_job = CFGJob(
                    block_head, node, current_instruction['destination'], block_irsb=irsb)
                self._insert_job(new_job)

                break


    def split_irsb(self, split_addr):
        self._current

    def _job_key(self, job):
        return job.addr

    def _job_queue_empty(self) -> None:
        l.info("Job queue is empty. Stopping.")

    # to be honest, we don't have any job to be done before the job is processed
    def _pre_job_handling(self, job: CFGJobBase) -> None:
        print("pre_job_handling")
        return

    def _process_job_and_get_successors(self, job_info: JobInfo) -> None:
        # per each job, creates edges in the CFG, and gets the successor(s) node
        # TODO: fix the shitty thing of adding jumpkind only at the end of block processing


        curr_statement = None
        group : pyvex.IRSB = job_info.job.block_irsb

        for statement in group.statements:
            
            if curr_statement:
                assert curr_statement == statement
            
            elif hasattr(statement, 'addr'):
                node : BasicBlock = self.model.get_any_node(
                    addr=statement.addr, anyaddr=True)

                working = self._current['working']
                
                if node:
                    assert isinstance(node, BasicBlock)
                    if isinstance(node, PhantomNode):
                        # CONVERT PHANTOM NODE TO NORMAL NODE
                        self.model.remove_node(node)                        
                        ir = pyvex.IRSB.empty_block(archinfo.ArchAMD64(), statement.addr, [statement])
                        node = BasicBlock(statement.addr, graph=self._current['function'].transition_graph, size = ir.size, irsb = ir)
                        working = node

                    elif node.get_head_statement() != statement:
                        # split the node in the cfg

                        (a, b) = self.split_irsb(node.irsb, statement.addr)
                        self.model.remove_node(node.addr, node)
                        self.model.add_node(a.addr, a)
                        self.model.add_node(b.addr, b)
                        working = b

                    assert statement == node.get_head_statement()              

                else:


                    if statement != group.statements[0] and isinstance(working, BasicBlock) and  \
                            ("Call" not in working._irsb.jumpkind) and ("Sig" not in working._irsb.jumpkind) and (not working.successors):
                        # TODO: assert (working.group.tail.addr + working.group.tail.size) == instr.addr
                        working.add_statement(statement, addr = statement.addr)                     
                        
                    else:
                        ir = pyvex.IRSB.empty_block(archinfo.ArchAMD64(), statement.addr, [statement])
                        node = BasicBlock(statement.addr, graph=self._current['function'].transition_graph, irsb = ir)
                        self._current['function']._transit_to(working, node)
                        working = node
                    pass
            else:
                working.add_statement(statement)

        curr_statement = working.next_statement(statement)
        working.jumpkind = group.jumpkind
        self._current['working'] = working
        return

    # def _handle_successor(self, job: CFGJobBase, successor: SimState, successors: List[SimState]) -> List[CFGJobBase]:
    #     successors = List[CFGJobBase]
    #     # per each successor generated, add it to the list of jobs
    #     return successors


class CFGJob():
    def __init__(self, addr: int, node: CFGNode, destination: int, block_irsb : pyvex.IRSB,
                 last_addr: Optional[int] = None,
                 src_node: Optional[CFGNode] = None, src_ins_addr: Optional[int] = None,
                 src_stmt_idx: Optional[int] = None, returning_source=None, syscall: bool = False):
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


class PhantomNode(CFGNode):
    def __init__(self, addr, cfg, function_address=None):
        super().__init__(addr, 0, cfg, simprocedure_name=None, no_ret=False, function_address=function_address, block_id=None,
                         irsb=None, soot_block=None, instruction_addrs=None, thumb=None, byte_string=None, is_syscall=False, name=None)


AnalysesHub.register_default('CFGInstrace', CFGInstrace)
