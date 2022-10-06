from collections import defaultdict
from dis import Instruction
from importlib.machinery import BYTECODE_SUFFIXES
from inspect import trace
from multiprocessing.sharedctypes import Value
from sqlite3 import Timestamp
from sre_parse import State
from tracemalloc import start
from typing import Dict, List, Optional
import collections
from copy import copy
import sys
from matplotlib.pyplot import pause

# LAST BASE: 0x7ff6153c0000


from sympy import Q, false, true
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

logging.basicConfig(stream=sys.stdout)
l = logging.getLogger(name=__name__)

if sys.argv[1]:
	l.setLevel(logging.getLevelName(sys.argv[1]))



# TODO: TI PREGO TROVA UN MODO MIGLIORE DI FARE IL BLOCK SPLIT FA SCHIFO
lifted = {}

splitted = set()
class CFGJob():
	def __init__(self, addr: int, destination: int, block_irsb : pyvex.IRSB, tid : int,
				 last_addr: Optional[int] = None,
				 src_node: Optional[CFGNode] = None, src_ins_addr: Optional[int] = None,
				 src_stmt_idx: Optional[int] = None, returning_source=None, syscall: bool = False, thread = '0',
				 start_sp: int = None, exit_sp = None):
		self.addr = addr
		self.destination = destination
		self.last_addr = last_addr
		self.src_node = src_node
		self.src_ins_addr = src_ins_addr
		self.src_stmt_idx = src_stmt_idx
		self.returning_source = returning_source
		self.syscall = syscall
		self.block_irsb = block_irsb
		self.thread = thread

		self.start_sp = start_sp
		self.exit_sp = exit_sp

		self.tid = tid
		

class CFGInstrace(ForwardAnalysis, CFGBase):
	"""
	The CFG is recovered from a list of executed instructions, and a trace
	of execution, one per thread
	"""
	tag = 'CFGInstrace'

	class State:
		def __init__(self, function = None, working = None, sp = None, entry_rsp = None):
			self.function = function
			self.working = working
			self.sp = sp
			self.rsp_at_entrypoint = entry_rsp


		def pp(self):
			print(hex(self.working.addr))

	class LiftingContext:
		def __init__(self):
			self.bytecode = b''
			self.start_rsp = None
			self.block_head = None



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

		self._callstack = defaultdict(lambda: None)
		self._current = defaultdict(lambda: self.State(function = None, working = None, sp = None))
		self._lifting_context = defaultdict(lambda: self.LiftingContext())
		self.lift_cache = {}
		self.pruned_jumps = set()        

		self._ins_trace = open(trace, "rb")	
		
		self.avoided_addresses = {}
		self.load_libraries(to_avoid_functions)

		self._analyze()   


	def next_irsb_block(self, ts):
		while True:
			curr_chunk = self._ins_trace.read(21)

			if curr_chunk:
				ip = struct.unpack('<Q', curr_chunk[:8])[0]
				sp = struct.unpack('<Q', curr_chunk[8:16])[0]
				tid =  struct.unpack('<I', curr_chunk[16:20])[0]
				is_dst = struct.unpack('<B', curr_chunk[20:21])[0]                    

				self._lifting_context[tid].start_rsp = sp if self._lifting_context[tid].start_rsp is None else self._lifting_context[tid].start_rsp
				self._lifting_context[tid].block_head = ip if self._lifting_context[tid].block_head is None else self._lifting_context[tid].block_head

				self._lifting_context[tid].bytecode += self.project.loader._instruction_map[ip][ts]

				if is_dst:
					dst = struct.unpack('<Q', self._ins_trace.read(8))[0]
					# end of the basic block, lift it to IRSB
					bytecode = self._lifting_context[tid].bytecode
					block_head = self._lifting_context[tid].block_head

					# check if the block is in lift cache
					if block_head in self.lift_cache.keys():
						irsb = self.lift_cache[block_head]	

					else:						
						irsb = pyvex.lift(bytecode, block_head, archinfo.ArchAMD64())

						while (irsb.size != len(bytecode)):
							# TODO: find a solution to pyvex not lifting each part of bytecode
							temp = pyvex.lift(bytecode[irsb.size:], irsb.addr + irsb.size, archinfo.ArchAMD64())
							irsb.extend(temp)

						self.lift_cache[block_head] = irsb
					
					# clear the lifting context for the current thread
					next_ip = dst
					exit_sp = sp
					start_sp = self._lifting_context[tid].start_rsp

					self._lifting_context[tid] = self.LiftingContext()

					assert start_sp is not None					

					# TODO: allow relifting without saving twice the bytecode
					lifted[block_head] = bytecode 

					if tid == 2:
						self.disasm(bytecode, block_head)
            
					break

			else:
				self._should_abort = True
				return (-1,-1,-1,-1,-1, -1)

		return (tid, block_head, irsb, next_ip, start_sp, exit_sp)

		


	def disasm(self, bytecode, block_head):
		#FOR DEBUGGING PURPOSES
		md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
		for i in md.disasm(bytecode, block_head):
			sys.stderr.write("0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str))
		sys.stderr.write("\n")

	def init_thread(self, tid, block_head):
		# Create the current function in the Function Manager
		l.info(f"TID {tid}: Initializing thread")
		initial = self.functions.function(addr=block_head, create=True)

		# create the self._current[tid] pair
		self._current[tid] = self.State(function = initial, working = None)


	def _pre_analysis(self):
		# build basic blocks from the instruction trace
		# need to emulate the trace for each thread
		# TODO: handle self modifying code

		self._initialize_cfg()

		# TODO: process in parallel each thread
		# First try with trace at timestamp 0 and thread 0
		(tid, block_head, irsb, next_ip, start_sp, exit_sp) = self.next_irsb_block(0)

		new_job = CFGJob(
		   block_head, next_ip, block_irsb=irsb, tid=tid, start_sp=start_sp, exit_sp=exit_sp)
		self._insert_job(new_job)



	def _job_key(self, job):
		return job.addr

	def _job_queue_empty(self) -> None:
		l.debug("Job queue is empty. Stopping.")

	def _pre_job_handling(self, job: CFGJob) -> None:
		target = job.destination
		tid = job.tid

		# Before going on with the job, we need to initialize the thread context
		# or to process the type of the previous working block 
		if self._current[tid].function is None:
			self.init_thread(tid, block_head=target)

		else:
			self.process_type(self._current[tid].working.prev_jump_target[tid], job)        


	# TODO: check if splitting works with call in the same function
	def process_group(self, job: CFGJob) -> None:

		l.debug(f"TID {job.tid} processing group {hex(job.addr)}")
		tid = job.tid
		group : pyvex.IRSB = job.block_irsb
		working : BasicBlock = self._current[tid].working

		if working is None:
			self._current[tid].rsp_at_entrypoint = job.start_sp

		# search for a node at the same address in the model
		assert len(self.model.get_all_nodes(addr = group.addr, anyaddr = True)) <= 1

		node : BasicBlock = self.model.get_any_node(addr = group.addr, anyaddr = True)

		if node is not None:
			# compare the found node with the current group
			if node.addr == group.addr:
				# the node is a phantom one and must be converted to a non phantom
				if node.is_phantom:
					node.phantom_to_node(group)
					working = node
				else:
					# TODO: handle self modifying code at the same address location
					while node._irsb.jumpkind == 'Ijk_Splitted':

						successors = node.successors()
						assert len(successors) == 1

						node = successors[0]                        

					working = node

			# TODO: differentiate between jump in middle of funciton or jump not to the first instruction \
			# of a block

			else:
				working = self.split_node(node, group.addr, tid)

		else:
			# there isn't any node with the address of the current group
			# just create a new node
			#l.debug(f"Creating new Basic Block for target {hex(group.addr)}")
			node = BasicBlock(group.addr, group.size, self._current[tid].function.transition_graph, irsb=group)


			self.model.add_node(node.addr, node)
			# check for the beginning of the program
			if working is not None:
				self._current[tid].function._transit_to(working, node)
			working = node

		self._current[tid].working = working
		self._current[tid].working.prev_jump_target[tid] = job.destination


		# set the stack pointer of exit from the basic block
		self._current[tid].sp = job.exit_sp

		assert self._current[tid].working is not None
		return     



	def split_node(self, node, target, tid) -> BasicBlock :       
		l.info(f"TID {tid}: Splitting node at " + hex(target))
		bytecode = lifted[node.addr]
		offset = target - node._irsb.addr

		car_bytecode = bytecode[:offset]
		cdr_bytecode = bytecode[offset:]

		# split the node
		(a, b) =  self._current[tid].function._split_node(node, target, car_bytecode, cdr_bytecode)

		# update the lifted bytecode
		lifted[node._irsb.addr] = car_bytecode
		lifted[target] = cdr_bytecode

		self.model.remove_node(node.addr, node)
		self.model.add_node(a.addr, a)
		self.model.add_node(b.addr, b)

		splitted.add(a.addr)
		splitted.add(b.addr)

		return b
	
	def should_target_be_tracked(self, target):
		for (x,y) in self.avoided_addresses.items():
			if x <= target and target < y:
				return False
		return True

	def process_type(self, target, job):
		
		tid = job.tid
		l.debug(f"TID {tid}: PROCESS_TYPE: function: {hex(self._current[tid].function.addr)}, working : {hex(self._current[tid].working.addr)}, target: {hex(target)}")
		
		working : BasicBlock = self._current[tid].working
		jumpkind = working._irsb.jumpkind
		rip = working._irsb.instruction_addresses[-1]

		# get all the possible jump targets from the current block
		jump_targets = working._irsb.constant_jump_targets.copy()
		jump_targets.add(target)
		jump_targets = set(filter(lambda x: not (working.addr <= x and x < working.addr + working.size), jump_targets))



		assert len(jump_targets) <= 2

		if jumpkind == 'Ijk_Boring':
			# herustic checks for call similarity

			# 1. pruned jump check
			if rip not in self.pruned_jumps:
				

				# check in before we are in a jmp stub 
				# since library function are not tracked, we need to fix the callstack
				if len(jump_targets) == 1 and not self.should_target_be_tracked(target): 


					self._current[tid].function.add_jumpout_site(self._current[tid].working)


					# get stub function from call stack and pop the callstack
					(caller, working_bb, ret_addr, sp, entry_rsp) = (self._callstack[tid].current.function, self._callstack[tid].current.working, self._callstack[tid].ret_addr, self._callstack[tid].current.sp, self._callstack[tid].current.rsp_at_entrypoint)					
					self._callstack[tid] = self._callstack[tid].pop()

					# add a fake return from the stub to the caller of the stub
					self._current[tid].function._fakeret_to(self._current[tid].working, caller)

					# set the new state
					self._current[tid] = self.State(function=caller, working=working_bb, sp = sp, entry_rsp=entry_rsp)

					l.info(f"TID {tid}: Rax dispatcher, popping {hex(ret_addr)}")
					l.debug(f"Function: {hex(self._current[tid].function.addr)}, {hex(self._current[tid].working.addr)}")
					return


				# it's not a call to a library function; apply heuristics for call similarity
				# 2. exclusion checks		

				if  self._current[tid].rsp_at_entrypoint != self._current[tid].sp or \
					self._current[tid].function.addr <= target and target <= rip or \
					rip <= target and target <= self._callstack[tid].ret_addr:

					self.pruned_jumps.add(rip)
					is_jump = True

				else:            
					# 3. inclusion checks
					func_map = self.functions._function_map

					# TODO: remember to remove the True in the if
					if  self.functions.function(addr=target) or \
						target <= self._current[tid].function.addr or \
						any(rip <= func and func <= target for func in func_map.keys()):
						
						l.info(f"TID {tid}: @{hex(rip)} Detected a call with call similarity heuristics with dst {hex(target)}")
						# Heuristics show it's a call. Fix the current function with the effectively called
						# without pushing anything on the callstack
						# TODO: check if it's necessarty to add a new edge 
						self._current[tid].function.add_jumpout_site(self._current[tid].working)      
						
						self._current[tid] = self.State(function=self.functions.function(target, create = True), working = None)
						is_jump = False
					
					# Default policy: it's a jump
					else:
						self.pruned_jumps.add(rip)
						is_jump = True
			
			else:
				is_jump = True

			if is_jump:
				for t in jump_targets:
					if t != target:
						assert len(self.model.get_all_nodes(addr = t, anyaddr = True)) <= 1
						node : BasicBlock = self.model.get_any_node(t, anyaddr=True)

						if node is not None:
							assert isinstance(node, BasicBlock)
							if not node.is_phantom and node.addr != t:
								node = self.split_node(node, t, tid)
						else:
							node = BasicBlock(addr = t, graph=self._current[tid].function.transition_graph, is_phantom = True)

							self.model.add_node(t, node)
						self._current[tid].function._transit_to(working, node)                       


		
		elif jumpkind == 'Ijk_Call': 
			# Check if it's a call to a library function

			return_address = working.addr + working.size

			if self.should_target_be_tracked(target):

				# Register the call site in the current function            
				called = self.functions.function(target, create = True)

				# Try to calculate the return from the call, so that it's possible to create the phantom node
				
				# Search for return node in model. If it doesn't exist, create a phantom one
				assert len(self.model.get_all_nodes(addr = return_address, anyaddr = True)) <= 1
				return_node = self.model.get_node(return_address)

				if return_node is None:
					return_node = BasicBlock(return_address, graph = self._current[tid].function.transition_graph, is_phantom = True)

					self.model.add_node(return_address, return_node)

				self._current[tid].function._transit_to(working, return_node)
				
				self.functions._add_call_to(self._current[tid].function.addr, working, target, \
					return_node, ins_addr = rip
					)    

				l.info(f"TID {tid}: " + hex(rip) + ": Processing call to " + hex(target) + " | ret addr at " + hex(return_address))

				if self._callstack[tid] is None:
					self._callstack[tid] = CallStack(rip, target, ret_addr=return_address, current=self._current[tid])

				else:
					self._callstack[tid] = self._callstack[tid].call(rip, target, retn_target=return_address,
								current=self._current[tid])

				
				
				self._current[tid] = self.State(function=called, working=None)
				assert self._current[tid].function.addr == target

				# TODO: handle calls in the middle of a block

			else:
				l.debug("Ignoring call @" + hex(rip) + " since it's to a library function")
		
		elif jumpkind == 'Ijk_Ret' and self._callstack[tid] is not None:
			# TODO: find out if the edges to be addedd are necessary 
			self._current[tid].function._add_return_site(self._current[tid].working)

			l.info(f"TID {tid}: Returning to " + hex(target))

			try:
				if not self.should_target_be_tracked(target):
					l.warning("Ignoring return since it's to a library function")
					return

				(func, working_bb, stack_ptr, rsp_entry) = (self._callstack[tid].current.function, self._callstack[tid].current.working, self._callstack[tid].current.sp, self._callstack[tid].current.rsp_at_entrypoint)

				assert self._callstack[tid].ret_addr == target

				# TODO: don't remember why there is this check, reintroduce it when i remember why it's there
				# assert self._callstack[tid].stack_ptr == self._current[tid].sp, hex(self._callstack[tid].stack_ptr) + " " + hex(self._current[tid].sp)
				
				self._callstack[tid] = self._callstack[tid].ret(target)
				self._current[tid] = self.State(function=func, working=working_bb, sp=stack_ptr, entry_rsp=rsp_entry)

				# for debug purposes
				# TODO: delete these lines
				node = self.model.get_node(target)
				assert node in self._current[tid].function.nodes
				
				
				pass
			except SimEmptyCallStackError:
				l.warning("Stack empty")


	# TODO: handle multiple timestamps for self modifying code 
	# From the execution trace, detects and create the next IR group to be processed
	def _get_successors(self, job: CFGJob) -> List[CFGJob]:

		self.process_group(job)

		(tid, block_head, irsb, next_ip, start_sp, exit_sp) = self.next_irsb_block(0)

		if self.should_abort:
			return []


		new_job = CFGJob(block_head, next_ip, irsb, thread = job.thread, tid=tid, start_sp=start_sp, exit_sp=exit_sp)

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
		print("End of analysis!")


AnalysesHub.register_default('CFGInstrace', CFGInstrace)


# strange pyvex behavior
'''

In [1]: import pyvex

In [2]: import archinfo

In [3]: head = 0x7ff6568de3a5

In [4]: bytecode = b'H\x8b\xc3L\x8d=Q\x1c\xff\xffI\x87\x84\xf7h\x92\x03\x00H\x85\xc0t\t'

In [5]: x = pyvex.lift(bytecode, head, archinfo.ArchAMD64(), opt_level=-1)

In [6]: x.constant_jump_targets
Out[6]: {140695990821807, 140695990821820, 140695990821829}

In [7]: [hex(x) for x in x.constant_jump_targets]
Out[7]: ['0x7ff6568de3bc', '0x7ff6568de3c5', '0x7ff6568de3af']

In [8]: x.pp()
IRSB {
   t0:Ity_I64 t1:Ity_I64 t2:Ity_I64 t3:Ity_I64 t4:Ity_I64 t5:Ity_I64 t6:Ity_I64 t7:Ity_I64 t8:Ity_I64 t9:Ity_I64 t10:Ity_I64 t11:Ity_I64 t12:Ity_I64 t13:Ity_I64 t14:Ity_I64 t15:Ity_I1 t16:Ity_I1 t17:Ity_I64 t18:Ity_I64 t19:Ity_I64 t20:Ity_I64 t21:Ity_I64 t22:Ity_I64

   00 | ------ IMark(0x7ff6568de3a5, 3, 0) ------
   01 | t9 = GET:I64(rbx)
   02 | PUT(rax) = t9
   03 | PUT(rip) = 0x00007ff6568de3a8
   04 | ------ IMark(0x7ff6568de3a8, 7, 0) ------
   05 | t0 = Add64(0x00007ff6568de3af,0xffffffffffff1c51)
   06 | PUT(r15) = t0
   07 | PUT(rip) = 0x00007ff6568de3af
   08 | ------ IMark(0x7ff6568de3af, 8, 0) ------
   09 | t13 = GET:I64(rsi)
   10 | t12 = Shl64(t13,0x03)
   11 | t14 = GET:I64(r15)
   12 | t11 = Add64(t14,t12)
   13 | t10 = Add64(t11,0x0000000000039268)
   14 | t3 = t10
   15 | t1 = LDle:I64(t3)
   16 | t2 = GET:I64(rax)
   17 | t5 = t1
   18 | t(4,4294967295) = CASle(t3 :: (t5,None)->(t2,None))
   19 | t15 = CasCmpNE64(t4,t5)
   20 | if (t15) { PUT(rip) = 0x7ff6568de3af; Ijk_Boring }
   21 | PUT(rax) = t1
   22 | PUT(rip) = 0x00007ff6568de3b7
   23 | ------ IMark(0x7ff6568de3b7, 3, 0) ------
   24 | t8 = GET:I64(rax)
   25 | t7 = GET:I64(rax)
   26 | t6 = And64(t8,t7)
   27 | PUT(cc_op) = 0x0000000000000014
   28 | PUT(cc_dep1) = t6
   29 | PUT(cc_dep2) = 0x0000000000000000
   30 | PUT(rip) = 0x00007ff6568de3ba
   31 | ------ IMark(0x7ff6568de3ba, 2, 0) ------
   32 | t17 = GET:I64(cc_op)
   33 | t18 = GET:I64(cc_dep1)
   34 | t19 = GET:I64(cc_dep2)
   35 | t20 = GET:I64(cc_ndep)
   36 | t21 = amd64g_calculate_condition(0x0000000000000004,t17,t18,t19,t20):Ity_I64
   37 | t16 = 64to1(t21)
   38 | if (t16) { PUT(rip) = 0x7ff6568de3c5; Ijk_Boring }
   39 | PUT(rip) = 0x00007ff6568de3bc
   40 | t22 = GET:I64(rip)
   NEXT: PUT(rip) = t22; Ijk_Boring
}
'''