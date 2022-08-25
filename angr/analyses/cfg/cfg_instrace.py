from collections import defaultdict
from dis import Instruction
from inspect import trace
from sqlite3 import Timestamp
from typing import Dict, List, Optional

from .cfg_job_base import CFGJobBase
from .cfg_base import CFGBase
from ..forward_analysis import ForwardAnalysis
from ...knowledge_plugins.cfg import CFGNode, MemoryDataSort, MemoryData, IndirectJump, IndirectJumpType
from angr.analyses.forward_analysis.job_info import JobInfo


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
        # TODO: update the method to insert just the first job per each thread
        # TODO: add multithread support

        self._initialize_cfg()

        # try with first thread
        tid = '0'

        th_trace = self._ins_trace['thread_exec_trace'][tid]
        

        first_address = None
        bytecode = b""

        # construct the first basic block

        while True:         
            curr_ins = th_trace.pop(0)

            if first_address is None:
                first_address = curr_ins['address']

            bytecode += self.project.loader._instruction_map[curr_ins['address']][curr_ins['timestamp']]

            if 'destination' in curr_ins.keys():
                        # build the irsb, add the node to the model, create the first job

                irsb = pyvex.lift(bytecode, first_address, archinfo.ArchAMD64())
                irsb.pp()

                node = CFGNode(first_address, len(bytecode), self.model, irsb=irsb)
                self.model.add_node(node.block_id, node)

                new_job = CFGJob(first_address, irsb.jumpkind, curr_ins['destination'])
                self._insert_job(new_job)

                break
    
        first_func = self.functions.function()
        
        IPython.embed()

    def _job_key(self, job):
        return job.addr           

    def _job_queue_empty(self) -> None:
        l.info("Job queue is empty. Stopping.")

    # to be honest, we don't have any job to be done before the job is processed
    def _pre_job_handling(self, job: CFGJobBase) -> None:
        return


    def _process_job_and_get_successors(self, job_info: JobInfo) -> None:
        # per each job, creates edges in the CFG, and gets the successor(s) node 


        return

    # def _handle_successor(self, job: CFGJobBase, successor: SimState, successors: List[SimState]) -> List[CFGJobBase]:
    #     successors = List[CFGJobBase]
    #     # per each successor generated, add it to the list of jobs
    #     return successors
        
class CFGJob():
    def __init__(self, addr: int, jumpkind: str, destination: int,
                 last_addr: Optional[int]=None,
                 src_node: Optional[CFGNode]=None, src_ins_addr:Optional[int]=None,
                 src_stmt_idx: Optional[int]=None, returning_source=None, syscall: bool=False):
        self.addr = addr
        self.jumpkind = jumpkind
        self.destination = destination
        self.last_addr = last_addr
        self.src_node = src_node
        self.src_ins_addr = src_ins_addr
        self.src_stmt_idx = src_stmt_idx
        self.returning_source = returning_source
        self.syscall = syscall

    



        


AnalysesHub.register_default('CFGInstrace', CFGInstrace)