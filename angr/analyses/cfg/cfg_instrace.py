from ast import Call
from collections import defaultdict
from dis import Instruction
from enum import Enum
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
import ipdb

# TODO: Save nodes in function and non in general CFGModel
# TODO: Check how to get nodes from function graph
# TODO: add callgraph in general CFGModel

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
l.setLevel(logging.getLevelName('WARNING'))




# TODO: TI PREGO TROVA UN MODO MIGLIORE DI FARE IL BLOCK SPLIT FA SCHIFO
lifted = {}

splitted = set()
class CFGJob():
	def __init__(self, opcode, destination: int, tid : int, addr : int):
		
		self.destination = destination
		self.tid = tid
		self.opcode = opcode
		self.addr = addr
	

class BasicBlockJob(CFGJob):
	def __init__(self, opcode, destination: int, tid: int, addr: int, start_sp: int = None, \
				 exit_sp=None, block_irsb: pyvex.IRSB = None):
		super().__init__(opcode, destination, tid, addr)
	
		self.block_irsb = block_irsb 

		self.start_sp = start_sp
		self.exit_sp = exit_sp

class SignalJob(CFGJob):
	def __init__(self, opcode, destination: int, tid: int, addr : int = None, signal_id : int = None):
		super().__init__(opcode, destination, tid, addr)
		self.signal_id = signal_id





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


	def __init__(self, trace, to_avoid_functions, normalize=False, base_state=None, detect_tail_calls=False, low_priority=False, model=None, OS = 'Linux', plt_dump = None):
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
		self.OS = OS 
	

		self._ins_trace = open(trace, "rb")	
		
		if OS == 'Linux':
			assert plt_dump is not None
			self.plt_sections = []
			with open(plt_dump, "rb") as f:
				while True:
					chunk = f.read(16)
					if len(chunk) == 0:
						break
					start = struct.unpack('<q', chunk[:8])[0]
					end = struct.unpack('<q', chunk[8:])[0]
					self.plt_sections.append((start, end))
					print(hex(start), hex(end))


		self.avoided_addresses = {}
		self.load_libraries(to_avoid_functions)


		self._job_dispatcher = {b"\x01": self.process_basic_block_job, b"\x02": self.process_raised_signal, b"\x03": self.process_return_from_signal}

		self._job_factory = {
			b"\x00": self.OP_new_instruction,
			b"\x01": self.OP_new_basic_block,
			b"\x02": self.OP_raise_signal,
			b"\x03": self.OP_return_signal
		}

		self._state_stack = defaultdict(lambda: [])
		self._analyze()   





	def process_basic_block_job(self, job: CFGJob):
		tid = job.tid

		if self.should_target_be_tracked(job.addr):
			if self._current[tid].function is None:
				self.init_thread(job.tid, block_head=job.addr)

			else:
				self.process_type(self._current[tid].working.prev_jump_target[tid], job)    

			self.process_group(job) 



	def is_plt_plt_got(self, target):
		return any(target >= start and target < end for start, end in self.plt_sections)


	def OP_new_instruction(self, opcode):

		curr_chunk = curr_chunk = self._ins_trace.read(20)
		ip = struct.unpack('<Q', curr_chunk[:8])[0]
		sp = struct.unpack('<Q', curr_chunk[8:16])[0]
		tid =  struct.unpack('<I', curr_chunk[16:20])[0]

		self._lifting_context[tid].start_rsp = sp if self._lifting_context[tid].start_rsp is None else self._lifting_context[tid].start_rsp
		self._lifting_context[tid].block_head = ip if self._lifting_context[tid].block_head is None else self._lifting_context[tid].block_head
		
		self._lifting_context[tid].bytecode += self.project.loader._instruction_map[ip]

		return (sp, tid)


	def OP_new_basic_block(self, opcode):

		(exit_sp, tid) = self.OP_new_instruction(opcode)

		dst = struct.unpack('<Q', self._ins_trace.read(8))[0]
		# end of the basic block, lift it to IRSB

		#TODO: DELETE THE REPLACE WHEN UNDERSTOOD HOW TO DEAL WITH PYVEX ISSUE				
		bytecode = self._lifting_context[tid].bytecode.replace(b"\xf3H\x0f\x1e", b"\x90\x90\x90\x90").replace(b"\xf3\x0f\x1e", b"\x90\x90\x90").replace(b"\xc8H\x89G", b"\x90" * 4).replace(b"\x0f\xc7d$@", b"\x90" * 5)

		block_head = self._lifting_context[tid].block_head

		# check if the block is in lift cache
		if block_head in self.lift_cache.keys():
			irsb = self.lift_cache[block_head]	

		else:						
			irsb = pyvex.lift(bytecode, block_head, archinfo.ArchAMD64())

			while (irsb.size != len(bytecode)):
				temp = pyvex.lift(bytecode[irsb.size:], irsb.addr + irsb.size, archinfo.ArchAMD64())
				if temp.size == 0:
					print("Extending with zero")
					IPython.embed()
				irsb.extend(temp)
					

			self.lift_cache[block_head] = irsb
		
		# clear the lifting context for the current thread
		next_ip = dst
		start_sp = self._lifting_context[tid].start_rsp
		assert start_sp is not None

		self._lifting_context[tid] = self.LiftingContext()		

		if l.level <= logging.DEBUG:
			if self.should_target_be_tracked(block_head):
				self.disasm(bytecode, block_head)


		# TODO: allow relifting without saving twice the bytecode
		lifted[block_head] = bytecode 


		return BasicBlockJob(opcode, next_ip, tid, block_head, block_irsb = irsb, start_sp = start_sp, exit_sp = exit_sp)

	def OP_raise_signal(self, opcode):
		chunk = self._ins_trace.read(21)
		
		sig_id = struct.unpack("<B", chunk[0:1])[0]
		src = struct.unpack("<Q", chunk [1:9])[0]
		target = struct.unpack("<Q", chunk [9:17])[0]
		tid = struct.unpack("<I", chunk[17:21])[0]		

		return SignalJob(opcode, destination=target, tid=tid, signal_id=sig_id)

	def OP_return_signal(self, opcode):
		chunk = self._ins_trace.read(12)
		
		target = struct.unpack("<Q", chunk[0:8])[0]
		tid = struct.unpack("<I", chunk [8:12])[0]


		return SignalJob(opcode, destination=target, tid=tid)			
	
	def process_return_from_signal(self, job: SignalJob):		
		tid = job.tid
		target = job.destination		
		# there we should add return site
		
		# restore state context
		(self._current[tid], self._callstack[tid]) = self._state_stack[tid].pop(0)
		return

	def process_raised_signal(self, job: SignalJob):
		tid = job.tid
		# for now just add a callsite
		# TODO: improve signal raise location
		self._current[tid].function._add_call_site(self._current[tid].working._irsb.instruction_addresses[-1], job.destination, None)

		self._state_stack[tid].insert(0, (self._current[tid], self._callstack[tid]))

		self._current[tid] = self.State()
		self._callstack[tid] = CallStack(bottom=True)

	def get_next_job(self):
		while True:
			opcode = self._ins_trace.read(1)
			if opcode:				
				job = self._job_factory[opcode](opcode)
				if isinstance(job, CFGJob):
					return job
			else:
				self._should_abort = True
				return

	def disasm(self, bytecode, block_head):
		#FOR DEBUGGING PURPOSES
		md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
		for i in md.disasm(bytecode, block_head):
			sys.stderr.write("0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str))
		sys.stderr.write("\n")

	def init_thread(self, tid, block_head):
		# Create the current function in the Function Manager
		l.info(f"TID {tid}: Initializing thread func: {hex(block_head)}")
		initial = self.functions.function(addr=block_head, create=True)

		# create the self._current[tid] pair
		self._current[tid] = self.State(function = initial, working = None)
		self._callstack[tid] = CallStack(bottom=True)


	def _pre_analysis(self):
		self._initialize_cfg()
		job = self.get_next_job()
		self._insert_job(job)



	def _job_key(self, job):
		return job.addr

	def _job_queue_empty(self) -> None:
		l.debug("Job queue is empty. Stopping.")

	def _pre_job_handling(self, job: CFGJob) -> None:
		try:
			self._job_dispatcher[job.opcode](job)
		except KeyError:
			raise NotImplementedError(f"Operation {job.opcode} not yet implemented")


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
				else:
					# TODO: handle self modifying code at the same address location
					while node._irsb.jumpkind == 'Ijk_Splitted':
						successors = node.successors()
						if len(successors) != 1:
							IPython.embed()
							
						assert len(successors) == 1

						node = successors[0]                        


			else:
				# check if we are jumping in the middle of a block, or in the middle of
				# an instruction

				if group.addr in node._irsb.instruction_addresses:
					# we are jumping in the middle of the block; need to split it
					node = self.split_node(node, group.addr, tid)
				else:
					# we are jumping in the middle of an instruction
					# need to create a new node
					l.info(f"TID {tid}: detected jump in middle of instruction at {hex(group.addr)}")
					node = BasicBlock(group.addr, group.size, irsb=group)
					self.model.add_node(node.addr, node)
				


		else:
			# there isn't any node with the address of the current group
			# just create a new node
			#l.debug(f"Creating new Basic Block for target {hex(group.addr)}")
			node = BasicBlock(group.addr, group.size, irsb=group)
			self.model.add_node(node.addr, node)

		
		assert node is not None

		if working is not None:
			self._current[tid].function._transit_to(working, node)

		self._current[tid].working = node
		self._current[tid].working.prev_jump_target[tid] = job.destination


		# set the stack pointer of exit from the basic block
		self._current[tid].sp = job.exit_sp

		assert self._current[tid].working is not None
		return     



	def split_node(self, node, split_addr, tid) -> BasicBlock :       
		l.info(f"TID {tid}: Splitting node at " + hex(split_addr))


		bytecode = lifted[node.addr]
		offset = split_addr - node._irsb.addr

		car_bytecode = bytecode[:offset]
		cdr_bytecode = bytecode[offset:]

		# split the node

		assert node._irsb.addr < split_addr and split_addr <= node._irsb.addr + node._irsb.size  

		# create the twos new IRSBs
		car_irsb = pyvex.lift(car_bytecode, node._irsb.addr, archinfo.ArchAMD64())
		cdr_irsb = pyvex.lift(cdr_bytecode, split_addr, archinfo.ArchAMD64())

		# set the jumpkind and the next field of the first IRSB
		car_irsb.next = cdr_irsb
		car_irsb.jumpkind = 'Ijk_Splitted'

		# create the new basic blocks
		car_bb = BasicBlock(car_irsb.addr, car_irsb.size, irsb=car_irsb)
		cdr_bb = BasicBlock(cdr_irsb.addr, cdr_irsb.size, irsb=cdr_irsb)
		
		# find functions that contains the original block
		funcs_with_block = filter(lambda x: self._current[tid].working.addr in x._local_block_addrs, self.functions._function_map.values())
		
		for func in funcs_with_block:
			func._split_node(node, car_bb, cdr_bb)
		

		# update the lifted bytecode
		lifted[node._irsb.addr] = car_bytecode
		lifted[split_addr] = cdr_bytecode

		self.model.remove_node(node.addr, node)
		self.model.add_node(car_bb.addr, car_bb)
		self.model.add_node(cdr_bb.addr, cdr_bb)

		splitted.add(car_bb.addr)
		splitted.add(cdr_bb.addr)

		return cdr_bb
	
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
					(caller, working_bb, ret_addr, exit_sp, entry_rsp) = (self._callstack[tid].current.function, self._callstack[tid].current.working, self._callstack[tid].ret_addr, self._callstack[tid].current.sp, self._callstack[tid].current.rsp_at_entrypoint)					

					self._callstack[tid] = self._callstack[tid].pop()


					# add a fake return from the stub to the caller of the stub
					self._current[tid].function._fakeret_to(self._current[tid].working, caller)

					# set the new state
					self._current[tid] = self.State(function=caller, working=working_bb, sp = exit_sp, entry_rsp=entry_rsp)

					l.info(f"TID {tid}: Jump stub, returning to {hex(ret_addr)}")
					l.debug(f"Function: {hex(self._current[tid].function.addr)}, {hex(self._current[tid].working.addr)}")
					return


				# it's not a call to a library function; apply heuristics for call similarity
				# 2. exclusion checks		

				if  self.OS == 'Linux' and self.is_plt_plt_got(target) and self.is_plt_plt_got(rip) or \
					self._current[tid].rsp_at_entrypoint != self._current[tid].sp or \
					self._current[tid].function.addr <= target and target <= rip or \
					any(rip <= target and target <= ret.addr for ret in self._current[tid].function.ret_sites):

					self.pruned_jumps.add(rip)
					is_jump = True

				else:            

					# inclusion checks
					# TODO: make the check with filter better
					if  self.functions.function(addr=target) or \
						target <= self._current[tid].function.addr or \
						len(list(filter(lambda x: self._current[tid].working.addr in x._local_block_addrs, self.functions._function_map.values()))) == 1 and \
						any(rip <= func and func <= target for func in self.functions._function_map.keys()):

						
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
							node = BasicBlock(addr = t, is_phantom = True)
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
					return_node = BasicBlock(return_address, is_phantom = True)

					self.model.add_node(return_address, return_node)
				
				self._current[tid].function._callout_sites.add(working)

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
		
		elif jumpkind == 'Ijk_Ret' and self._callstack[tid]:
			# TODO: find out if the edges to be addedd are necessary 
			self._current[tid].function._add_return_site(self._current[tid].working)

			callee = self._current[tid].function

			l.info(f"TID {tid}: Returning to {hex(target)} | Depth: {len(self._callstack[tid])}")

			try:
				if not self.should_target_be_tracked(target):
					l.warning("Ignoring return since it's to a library function")
					return
				
				stack_top = self._callstack[tid]
				self._callstack[tid] = self._callstack[tid].pop()

				# restore status after return
				assert stack_top.ret_addr == target, IPython.embed()

				(func, working_bb, stack_ptr, rsp_entry) = (stack_top.current.function, stack_top.current.working, stack_top.current.sp, stack_top.current.rsp_at_entrypoint)
				# TODO: don't remember why there is this check, reintroduce it when i remember why it's there
				# assert self._callstack[tid].stack_ptr == self._current[tid].sp, hex(self._callstack[tid].stack_ptr) + " " + hex(self._current[tid].sp)
				self._current[tid] = self.State(function=func, working=working_bb, sp=stack_ptr, entry_rsp=rsp_entry)				
				
				# it's returning, so remove the call from the callout and put it in the call list

				self._current[tid].function._callout_sites.remove(working_bb)
				# check if it's a direct or an indirect call; if indirect, doesn't save target
				self.functions._add_call_to(self._current[tid].function.addr, working_bb, callee.addr, \
					self.model.get_node(target), ins_addr = rip
					)
				
			except SimEmptyCallStackError:
				l.warning("Stack empty")

		elif jumpkind == "Ijk_Sys_syscall":
			# don't anything. transition graph will be update in process group
			pass 

		else:
			raise NotImplementedError("Unsupported jumpkind: " + jumpkind)


	# From the execution trace, detects and create the next IR group to be processed
	def _get_successors(self, job: CFGJob) -> List[CFGJob]:

		job = self.get_next_job()

		if self.should_abort:
			return []

		return [job]
		

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