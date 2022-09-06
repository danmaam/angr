from collections import defaultdict
from dis import Instruction
from inspect import trace
from sqlite3 import Timestamp
from typing import Dict, List, Optional

from sympy import false, true

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

        th_trace = self._ins_trace['thread_exec_trace'][tid]

        first_address = None
        bytecode = b""

        instructions = []
        instruction_info = []

        # construct the first basic block

        while True:
            curr_ins = th_trace.pop(0)

            if first_address is None:
                first_address = curr_ins['address']

            instructions.append(
                self.project.loader._instruction_map[curr_ins['address']][curr_ins['timestamp']])
            instruction_info.append(curr_ins)

            if 'destination' in curr_ins.keys():
                # build the irsb, add the node to the model, create the first job

                bytecode = b''.join(instructions)
                irsb = pyvex.lift(bytecode, first_address,
                                  archinfo.ArchAMD64())

                # create the current pair
                initial = self.functions.function(
                    addr=first_address, create=True)
                self._current = {}

                # create the first basic block
                first_block = BasicBlock(
                    first_address, graph=initial.transition_graph)

                self._current['function'] = initial
                self._current['working'] = first_block

                node = CFGNode(first_address, len(
                    bytecode), self.model, irsb=irsb)

                new_job = CFGJob(
                    first_address, node, curr_ins['destination'], instructions, instruction_info)
                self._insert_job(new_job)

                break

        IPython.embed()

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

        leader_address = job_info.instruction_info[0]['address']

        # implementation of PROCESS_GROUP of CFGGrind
        curr_instr = None

        for instr in zip(job_info.job.instruction_info, job_info.job.instructions):

            if curr_instr:
                assert curr_instr == instr
            else:
                infos = instr[0]
                bytecode = instr[1]

                node = self.model.get_any_node(
                    addr=infos['address'], anyaddr=True)

                working = self._current['working']
                
                if node:
                    if isinstance(node, PhantomNode):
                        # CONVERT PHANTOM NODE TO NORMAL NODE
                        self.model.remove_node(node)
                        ir = pyvex.lift(bytecode, infos['address'], archinfo.ArchAMD64())
                        node = BasicBlock(infos['address'], graph=self._current['function'].transition_graph, size = ir.size, irsb = ir)
                        working = node
                    elif node.addr != infos['address']:
                        # split the node in the cfg

                        (a, b) = self.split_irsb(node.irsb, infos['address'])
                        self.model.remove_node(node.addr, node)
                        self.model.add_node(a.addr, a)
                        self.model.add_node(b.addr, b)
                        working = b

                    # assert first_instruction == group leader                

                else:
                    ir = pyvex.lift(bytecode, infos['address'], archinfo.ArchAMD64())

                    if infos['address'] != leader_address and isinstance(working, BasicBlock) and  \
                            ("Call" not in working.irsb.jumpkind) and ("Sig" not in working.irsb.jumpkind) and (not working.successors):
                        # TODO: assert tail address is equal to the current instruction
                        working.add_bytecode(bytecode, archinfo.ArchAMD64())                       
                        
                    else:
                        node = BasicBlock(infos['address'], graph=self._current['function'].transition_graph, irsb = ir)
                        self._current['function']._transit_to(working, node)
                        working = node
                    pass

        self._current['working'] = working
        return

    # def _handle_successor(self, job: CFGJobBase, successor: SimState, successors: List[SimState]) -> List[CFGJobBase]:
    #     successors = List[CFGJobBase]
    #     # per each successor generated, add it to the list of jobs
    #     return successors


class CFGJob():
    def __init__(self, addr: int, node: CFGNode, destination: int, instructions: List, instruction_info: List,
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
        self.instruction_info = instruction_info
        self.instructions = instructions


class PhantomNode(CFGNode):
    def __init__(self, addr, cfg, function_address=None):
        super().__init__(addr, 0, cfg, simprocedure_name=None, no_ret=False, function_address=function_address, block_id=None,
                         irsb=None, soot_block=None, instruction_addrs=None, thumb=None, byte_string=None, is_syscall=False, name=None)


AnalysesHub.register_default('CFGInstrace', CFGInstrace)
