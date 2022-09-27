import logging
from typing import List
import pyvex
import archinfo
import IPython

l = logging.getLogger(name=__name__)


def repr_addr(addr):
	if isinstance(addr, int):
		return hex(addr)
	return repr(addr)


class CodeNode:

	__slots__ = ['addr', 'size', '_graph', 'thumb', '_hash']

	def __init__(self, addr, size, graph=None, thumb=False):
		self.addr = addr
		self.size = size
		self.thumb = thumb
		self._graph = graph

		self._hash = None

	def __len__(self):
		return self.size

	def __eq__(self, other):
		if type(other) is Block:  # pylint: disable=unidiomatic-typecheck
			raise TypeError("You do not want to be comparing a CodeNode to a Block")
		return type(self) is type(other) and \
			self.addr == other.addr and \
			self.size == other.size and \
			self.is_hook == other.is_hook and \
			self.thumb == other.thumb

	def __ne__(self, other):
		return not self == other

	def __cmp__(self, other):
		raise TypeError("Comparison with a code node")

	def __hash__(self):
		if self._hash is None:
			self._hash = hash((self.addr, self.size))
		return self._hash

	def successors(self) -> List["CodeNode"]:
		if self._graph is None:
			raise ValueError("Cannot calculate successors for graphless node")
		return list(self._graph.successors(self))

	def predecessors(self):
		if self._graph is None:
			raise ValueError("Cannot calculate predecessors for graphless node")
		return list(self._graph.predecessors(self))

	def __getstate__(self):
		return (self.addr, self.size)

	def __setstate__(self, dat):
		self.__init__(*dat)

	is_hook = None


class BasicBlock(CodeNode):
	def __init__(self, addr=0, size=0, graph=None, thumb=False, irsb:pyvex.IRSB=None, instructions=None, is_phantom=False):
		super().__init__(addr, size, graph=graph, thumb=thumb)
		if not is_phantom:
			assert graph is not None and irsb is not None
			if irsb is not None:
				assert isinstance(irsb, pyvex.IRSB)
				self._irsb = irsb
			else:
				self._irsb = pyvex.IRSB.empty_block(archinfo.ArchAMD64(), addr = addr, jumpkind='Ijk_NoDecode')
				


			self._graph.add_node(self)

		self.is_phantom = is_phantom

	# TODO: for now just add the jumpkind at the end of the block construction
	def add_statement(self, statement, addr = None, tyenv = None, jumpkind = None):
		assert not self.is_phantom
		# TODO: make this process faster
		if addr is None:
			addr = self._irsb.size + self._irsb.addr

		empty = pyvex.IRSB.empty_block(archinfo.ArchAMD64(), addr, [statement], tyenv=tyenv, jumpkind = jumpkind if jumpkind else self._irsb.jumpkind)
		self._irsb.extend(empty)

	def has_statement(self, idx, statement):
		assert not self.is_phantom
		return (idx, statement) in enumerate(self._irsb.statements)

		
	def append_jumpkind(self, jumpkind):
		assert not self.is_phantom
		self._irsb.jumpkind = jumpkind

	def get_head_statement(self):
		assert self._irsb != None and not self.is_phantom
		return self._irsb.statements[0] if self._irsb.stmts_used > 0 else None

	#TODO: please improve this shitty thing
	def next_statement(self, statement):
		assert not self.is_phantom
		for idx, elem in enumerate(self._irsb.statements):
			if elem == statement:
				return self._irsb.statements[idx+1] if idx + 1 < len(self._irsb.statements) else None
		
	
	def phantom_to_node(self, irsb, thumb = False):
		assert self.is_phantom
		self.addr = irsb.addr
		self.size = irsb.size
		self.thumb = thumb
		self._irsb = irsb
		self.is_phantom = False

	def pp(self):
		self._irsb.pp()
	

		


class BlockNode(CodeNode):

	__slots__ = ['bytestr']

	is_hook = False
	def __init__(self, addr, size, bytestr=None, **kwargs):
		super(BlockNode, self).__init__(addr, size, **kwargs)
		self.bytestr = bytestr

	def __repr__(self):
		return '<BlockNode at %s (size %d)>' % (repr_addr(self.addr), self.size)

	def __getstate__(self):
		return (self.addr, self.size, self.bytestr, self.thumb)

	def __setstate__(self, dat):
		self.__init__(*dat[:-1], thumb=dat[-1])


class SootBlockNode(BlockNode):

	__slots__ = ['stmts']

	def __init__(self, addr, size, stmts, **kwargs):
		super(SootBlockNode, self).__init__(addr, size, **kwargs)
		self.stmts = stmts

		assert (stmts is None and size == 0) or (size == len(stmts))

	def __repr__(self):
		return '<SootBlockNode at %s (%d statements)>' % (repr_addr(self.addr), self.size)

	def __getstate__(self):
		return self.addr, self.size, self.stmts

	def __setstate__(self, data):
		self.__init__(*data)


class HookNode(CodeNode):

	__slots__ = ['sim_procedure']

	is_hook = True
	def __init__(self, addr, size, sim_procedure, **kwargs):
		"""
		:param type sim_procedure: the the sim_procedure class
		"""
		super(HookNode, self).__init__(addr, size, **kwargs)
		self.sim_procedure = sim_procedure

	def __repr__(self):
		return '<HookNode %r at %s (size %s)>' % (self.sim_procedure, repr_addr(self.addr), self.size)

	def __hash__(self):
		return hash((self.addr, self.size, self.sim_procedure))

	def __eq__(self, other):
		return super(HookNode, self).__eq__(other) and \
			self.sim_procedure == other.sim_procedure

	def __getstate__(self):
		return (self.addr, self.size, self.sim_procedure)

	def __setstate__(self, dat):
		self.__init__(*dat)

class SyscallNode(HookNode):
	is_hook = False
	def __repr__(self):
		return '<SyscallNode %r at %#x (size %s)>' % (self.sim_procedure, self.addr, self.size)

from .block import Block
