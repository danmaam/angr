from ast import Call
from collections import defaultdict
from dis import Instruction
from enum import Enum
from importlib.machinery import BYTECODE_SUFFIXES
from inspect import trace
from multiprocessing.sharedctypes import Value
from os import abort
from sqlite3 import Timestamp
from sre_parse import State
from threading import current_thread
from tracemalloc import start
from typing import Dict, List, Optional
import collections
from copy import copy
import sys
from matplotlib.pyplot import pause
import ipdb
import re

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

logging.basicConfig(stream=sys.stdout)
l = logging.getLogger(name=__name__)
l.setLevel(logging.getLevelName('WARNING'))


#TODO: heuristics doesn't work well since stackpointer is took after returns and calls



splitted = set()
class CFGJob():
	def __init__(self, destination: int, tid : int, addr : int, process):
		
		self.destination = destination
		self.tid = tid
		self.addr = addr
		self.process = process
		
	

class InstructionJob(CFGJob):
	def __init__(self, destination: int, tid: int, addr: int, process, sp: int):
		super().__init__(destination, tid, addr, process)
		self.sp = sp

	

class BasicBlockJob(CFGJob):
	def __init__(self, destination: int, tid: int, addr: int, process, bytecode, start_sp: int = None, \
				 exit_sp=None):
		super().__init__(destination, tid, addr, process)
	 
		self.bytecode = bytecode
		self.entryRSP = start_sp
		self.exitRSP = exit_sp
		self.block_irsb = None

class SignalJob(CFGJob):
	def __init__(self, destination: int, tid: int, addr : int, process, signal_id : int = None):
		super().__init__(destination, tid, addr, process)
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
			self.entryRSP = None
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
		self.perThreadContext = defaultdict(lambda: self.LiftingContext())
		self.lift_cache = defaultdict(lambda: None)
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


		self._job_dispatcher = {b"\x01": self.ProcessNewBasicBlock, b"\x02": self.process_raised_signal, b"\x03": self.process_return_from_signal}

		self._job_factory = {
			b"\x00": self.OPNewInstruction,
			b"\x01": self.OPControlFlowInstruction,
			b"\x02": self.OPRaisedSignal,
			b"\x03": self.OPReturnFromSignal
		}

		self._state_stack = defaultdict(lambda: [])
		self._analyze()   



	def ProcessNewBasicBlock(self, job: BasicBlockJob):
		tid = job.tid
		job.block_irsb = self.LiftBasicBlock(job)

		if self._current[tid].function is None:
			self.init_thread(job.tid, block_head=job.addr)	

		if self.should_target_be_tracked(job.addr):		
			self.process_group(job)
			self.process_type(job.destination, job.tid)

		elif self.should_target_be_tracked(job.destination):
			self.process_group(job, transit_to = False)
			self.process_type(job.destination, job.tid, outside = True)



	def is_plt_plt_got(self, target):
		return any(target >= start and target < end for start, end in self.plt_sections)
	
	def NewInstruction(self, job: InstructionJob):
		return

	def LiftBasicBlock(self, job: BasicBlockJob):
		head = job.addr
		bytecode = job.bytecode

		size = len(bytecode)

		# Take the block from the lifting cache
		irsb = self.lift_cache[head]	

		if not irsb:						
			irsb = pyvex.lift(bytecode, head, archinfo.ArchAMD64())

			# Hack to deal with pyvex bug on rep instructions
			while (irsb.size != size):
				temp = pyvex.lift(bytecode[irsb.size:], irsb.addr + irsb.size, archinfo.ArchAMD64())

				# Check that pyvex effectively lifted code
				if temp.size == 0:
					# We have to nop the instruction causing problems
					md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
					i = next(md.disasm(bytecode[irsb.size:], irsb.addr + irsb.size))
					l.warning(f"{hex(i.address)}, {i.mnemonic}, {i.op_str} replaced with Nop Instructions")
					l.warning(f"Bytecode: {bytecode[irsb.size:]}")
					bad_instr_size = i.size
					bytecode = bytecode[:irsb.size] + b"\x90" * bad_instr_size + bytecode[irsb.size + bad_instr_size:]

				irsb.extend(temp)
					
			# Save the lifted block in the lift cache
			self.lift_cache[head] = irsb

		# Clear the lift context for the current thread

		if l.level <= logging.DEBUG:
			self.disasm(bytecode, head)
			pass

		return irsb


	def OPNewInstruction(self, check = True):

		curr_chunk = self._ins_trace.read(20)
		ip = struct.unpack('<Q', curr_chunk[:8])[0]
		sp = struct.unpack('<Q', curr_chunk[8:16])[0]
		tid =  struct.unpack('<I', curr_chunk[16:20])[0]

		self.perThreadContext[tid].entryRSP = sp if self.perThreadContext[tid].entryRSP is None else self.perThreadContext[tid].entryRSP
		self.perThreadContext[tid].block_head = ip if self.perThreadContext[tid].block_head is None else self.perThreadContext[tid].block_head
		
		self.perThreadContext[tid].bytecode += self.project.loader.instruction_memory.load_instruction(ip)

		# Check if we covered part of a block or not
		size = len(self.perThreadContext[tid].bytecode)
		head = self.perThreadContext[tid].block_head

		if check and head + size in self.model._nodes_by_addr:
			return self.GenerateBasicBlockJob(sp, tid)

		return [InstructionJob(0, tid, ip, self.NewInstruction, sp)]


	def OPControlFlowInstruction(self):

		job = self.OPNewInstruction(check = False)[0]
		(tid, exitRSP) = (job.tid, job.sp)

		destination = struct.unpack('<Q', self._ins_trace.read(8))[0]

		return self.GenerateBasicBlockJob(exitRSP, tid, destination)


	def GenerateBasicBlockJob(self, exitRSP, tid, destination = None):

		head = self.perThreadContext[tid].block_head
		bytecode = self.perThreadContext[tid].bytecode

		size = len(bytecode)
		
		entryRSP = self.perThreadContext[tid].entryRSP

		# Clear the lift context for the current thread

		if destination is None:
			destination = head + size
		
		# Reset instruction context
		self.perThreadContext[tid] = self.LiftingContext()

		return [BasicBlockJob(destination = destination, tid = tid, addr = head, process = self.ProcessNewBasicBlock, bytecode = bytecode, start_sp = entryRSP, exit_sp = exitRSP)]


	def OPRaisedSignal(self):
		chunk = self._ins_trace.read(21)
		
		sig_id = struct.unpack("<B", chunk[0:1])[0]
		src = struct.unpack("<Q", chunk [1:9])[0]
		target = struct.unpack("<Q", chunk [9:17])[0]
		tid = struct.unpack("<I", chunk[17:21])[0]		

		return [SignalJob(target, tid, None, self.process_raised_signal, signal_id=sig_id)]

	def OPReturnFromSignal(self):
		chunk = self._ins_trace.read(12)
		
		target = struct.unpack("<Q", chunk[0:8])[0]
		tid = struct.unpack("<I", chunk [8:12])[0]


		return [SignalJob(target, tid, None, self.process_return_from_signal)]			
	
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
		self._current[tid].function._add_call_site(self._current[tid].working._irsb.instruction_addresses[-1], job.destination, None)

		self._state_stack[tid].insert(0, (self._current[tid], self._callstack[tid]))

		self._current[tid] = self.State()
		self._callstack[tid] = CallStack(bottom=True)

	def get_next_job(self):
		while True:
			opcode = self._ins_trace.read(1)
			if opcode:				
				job = self._job_factory[opcode]()
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
		for j in job:
			self._insert_job(j)


	def _job_key(self, job):
		return job.addr

	def _job_queue_empty(self) -> None:
		l.debug("Job queue is empty. Stopping.")

	def _pre_job_handling(self, job: CFGJob) -> None:
		job.process(job)


	def process_group(self, job: BasicBlockJob, transit_to = True) -> None:
		l.debug(f"TID {job.tid} processing group {hex(job.addr)} in function {hex(self._current[job.tid].function.addr)}")
		tid = job.tid
		group : pyvex.IRSB = job.block_irsb
		working : BasicBlock = self._current[tid].working
			
		if working is None:
			self._current[tid].rsp_at_entrypoint = job.entryRSP

		# search for a node at the same address in the model
		assert len(self.model.get_all_nodes(addr = group.addr, anyaddr = True)) <= 1

		node : BasicBlock = self.model.get_any_node(addr = group.addr, anyaddr = True)

		if node is not None:
			# compare the found node with the current group
			if node.addr == group.addr:
				# the node is a phantom one and must be converted to a non phantom
				
				if node.is_phantom:
					node.phantom_to_node(group)	

				assert node.size == group.size		

			else:
				# check if we are jumping in the middle of a block, or in the middle of
				# an instruction
				if group.addr in node._irsb.instruction_addresses:
					# Jumping to an instruction in the middle of the block. Split it.
					(car_bb, cdr_bb) = self.split_node(node, group.addr, tid)
					node = cdr_bb
					if working is not None and working.addr == car_bb.addr:
						working = car_bb
				else:
					# Jumping into the middle of an instruction. Create a new node.
					l.info(f"TID {tid}: detected jump in middle of instruction at {hex(group.addr)}")
					node = BasicBlock(group.addr, group.size, irsb=group)
					self.model.add_node(node.addr, node)		


		else:
			# No node exists for the current block. Create it.
			node = BasicBlock(group.addr, group.size, irsb=group)
			self.model.add_node(node.addr, node)

		
		assert node is not None

		if transit_to:
			if working is not None:
				self._current[tid].function._transit_to(working, node)
			else:
				self._current[tid].function._register_nodes(True, node)

		self._current[tid].working = node
		self._current[tid].working.prev_jump_target[tid] = job.destination


		# set the stack pointer of exit from the basic block
		self._current[tid].sp = job.exitRSP

		assert self._current[tid].working is not None
		return     



	def split_node(self, node, split_addr, tid) -> BasicBlock :       
		l.info(f"TID {tid}: Splitting node at " + hex(split_addr))

		bytecode = self.project.loader.instruction_memory.load(node.addr, node.size)
		offset = split_addr - node._irsb.addr

		car_bytecode = bytecode[:offset]
		cdr_bytecode = bytecode[offset:]

		# split the node

		assert node._irsb.addr < split_addr and split_addr <= node._irsb.addr + node._irsb.size  

		# create the twos new IRSBs
		car_irsb = pyvex.lift(car_bytecode, node._irsb.addr, archinfo.ArchAMD64())
		cdr_irsb = pyvex.lift(cdr_bytecode, split_addr, archinfo.ArchAMD64())

		# create the new basic blocks
		car_bb = BasicBlock(car_irsb.addr, car_irsb.size, irsb=car_irsb)
		cdr_bb = BasicBlock(cdr_irsb.addr, cdr_irsb.size, irsb=cdr_irsb)
		
		# find functions that contains the original block
		funcs_with_block = filter(lambda x: node.addr in x._local_block_addrs, self.functions._function_map.values())

		for func in funcs_with_block:
			func._split_node(node, car_bb, cdr_bb)

		# clear the lift cache
		self.lift_cache[node.addr] = None
		self.lift_cache[node._irsb.addr] = car_irsb
		self.lift_cache[split_addr] = cdr_irsb


		self.model.remove_node(node.addr, node)
		self.model.add_node(car_bb.addr, car_bb)
		self.model.add_node(cdr_bb.addr, cdr_bb)

		splitted.add(car_bb.addr)
		splitted.add(cdr_bb.addr)

		return (car_bb, cdr_bb)
	
	def should_target_be_tracked(self, target):
		for (x,y) in self.avoided_addresses.items():
			if x <= target and target < y:
				return False
		return True
	
	

	def process_type(self, target, tid, outside=False):
		
		working : BasicBlock = self._current[tid].working
		jumpkind = working._irsb.jumpkind
		rip = working._irsb.instruction_addresses[-1]

		def Ijk_Call(self, target, tid):			# Check if it's a call to a library function

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

				self._callstack[tid] = self._callstack[tid].call(rip, target, retn_target=return_address,
								current=self._current[tid])				
				
				self._current[tid] = self.State(function=called, working=None)
				assert self._current[tid].function.addr == target

			else:
				l.debug("Ignoring call @" + hex(rip) + " since it's to a library function")

		def Ijk_Boring(self, target, tid):
			jump_targets = working._irsb.constant_jump_targets.copy()
			jump_targets.add(target)
			jump_targets = set(filter(lambda x: not (working.addr <= x and x < working.addr + working.size), jump_targets))

			assert len(jump_targets) <= 2
			# herustic checks for call similarity

			# 1. pruned jump check
			if rip not in self.pruned_jumps:
				
				# check in before we are in a jmp stub 
				# since library function are not tracked, we need to fix the callstack
				if len(jump_targets) == 1 and not self.should_target_be_tracked(target): 

					self._current[tid].function.add_jumpout_site(self._current[tid].working)
					callee = self._current[tid].function
					
					# get stub function from call stack and pop the callstack
					(caller, working_bb, ret_addr, exit_sp, entry_rsp) = (self._callstack[tid].current.function, self._callstack[tid].current.working, self._callstack[tid].ret_addr, self._callstack[tid].current.sp, self._callstack[tid].current.rsp_at_entrypoint)					

					self._callstack[tid] = self._callstack[tid].pop()

					# add a fake return from the stub to the caller of the stub
					self._current[tid].function._fakeret_to(self._current[tid].working, caller)

					# set the new state
					self._current[tid] = self.State(function=caller, working=working_bb, sp = exit_sp, entry_rsp=entry_rsp)

					try:
						self._current[tid].function._callout_sites.remove(working_bb)
					except:
						pass
					
					# check if it's a direct or an indirect call; if indirect, doesn't save target
					self.functions._add_call_to(self._current[tid].function.addr, 	
												working_bb, \
												callee.addr, \
												self.model.get_node(target), ins_addr = rip
												)

					l.info(f"TID {tid}: Jump stub, returning to {hex(ret_addr)}")



					l.debug(f"Function: {hex(self._current[tid].function.addr)}, {hex(self._current[tid].working.addr)}")
					return

				assert self.should_target_be_tracked(target)
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

			if is_jump and not outside:
				for t in jump_targets:
					if t != target:
						assert len(self.model.get_all_nodes(addr = t, anyaddr = True)) <= 1
						node : BasicBlock = self.model.get_any_node(t, anyaddr=True)

						if node is not None:
							assert isinstance(node, BasicBlock)
							if not node.is_phantom and node.addr != t:
								(_, node) = self.split_node(node, t, tid)
						else:
							node = BasicBlock(addr = t, is_phantom = True)
							self.model.add_node(t, node)



						self._current[tid].function._transit_to(working, node)    

		def Ijk_Nop(self, target, tid):

			return

		def Ijk_Ret(self, target, tid):
			# TODO: find out if the edges to be addedd are necessary 

			self._current[tid].function._add_return_site(self._current[tid].working)

			callee = self._current[tid].function

			l.info(f"TID {tid}: Returning to {hex(target)} | Depth: {len(self._callstack[tid])}")

			try:
				
				stack_top = copy(self._callstack[tid])
				
				self._callstack[tid] = self._callstack[tid].pop()

				# restore status after return
				try:
					assert stack_top.ret_addr == target, f"TID {tid}: ret_addr: {hex(stack_top.ret_addr)}, actual_target: {hex(target)}, func: {hex(self._current[tid].function.addr)}"
				except Exception as e:
					if not self.should_target_be_tracked(target):
						l.warning(f"TID {tid}: ret_addr: {hex(stack_top.ret_addr)} ignored since it's to a library function")
					else:
						raise e

				(func, working_bb, stack_ptr, rsp_entry) = (stack_top.current.function, stack_top.current.working, stack_top.current.sp, stack_top.current.rsp_at_entrypoint)
				self._current[tid] = self.State(function=func, \
												working=working_bb, \
												sp=stack_ptr, \
												entry_rsp=rsp_entry)


				# it's returning, so remove the call from the callout and put it in the call list
				try:
					self._current[tid].function._callout_sites.remove(working_bb)
				except:
					pass
				# check if it's a direct or an indirect call; if indirect, doesn't save target
				self.functions._add_call_to(self._current[tid].function.addr, 	
											working_bb, \
											callee.addr, \
											self.model.get_node(target), ins_addr = rip
											)

			except SimEmptyCallStackError:
				l.warning("Stack empty")

		l.debug(f"TID {tid}: PROCESS_TYPE: function: {hex(self._current[tid].function.addr)}, working : {hex(self._current[tid].working.addr)}, target: {hex(target)}")

		OperationSwitcher = {
			"Ijk_Call": Ijk_Call,
			"Ijk_Boring": Ijk_Boring,
			"Ijk_Sys_syscall": Ijk_Nop,
			"Ijk_Yield": Ijk_Nop,
			"Ijk_Ret": Ijk_Ret
		}
		try:
			OperationSwitcher[jumpkind](self, target, tid)
		except KeyError:
			l.error(f"Unknown jumpkind {jumpkind}")
			exit(-1)

	# From the execution trace, detects and create the next IR group to be processed
	def _get_successors(self, job: CFGJob) -> List[CFGJob]:
		job = self.get_next_job()

		if self.should_abort:
			return []
		
		return job
		

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