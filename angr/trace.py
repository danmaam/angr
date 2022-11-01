from cle import Backend, register_backend, memory
from cle.errors import CLEError
import logging
import struct
from collections import defaultdict
import archinfo
import IPython

l = logging.getLogger(name=__name__)

__all__ = ('DynamicRecoveredInstructions',)

class DynamicRecoveredInstructions(Backend):
	"""
	Representation of the instruction trace of a binary obtained after 
	dynamic execution of the binary (e.g. Intel PIN, Valgrind)
	"""

	class Memory:
		def __init__(self):
			self.map = {}
			self.instruction_size = {}
		
		def store_instruction(self, address, instruction):
			self.instruction_size[address] = len(instruction)
			self.store(address, instruction)

		def store(self, address, data):
			for i in range(len(data)):
				self.map[address + i] = data[i]

		def load(self, address, len):
			data = b""
			for i in range(len):
				data += (self.map[address + i]).to_bytes(1, 'big')
			return data

		def load_instruction(self, address):
			return self.load(address, self.instruction_size[address])


	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		#TODO: determine instruction size from opcode
		#load into memory 

		self.loader.instruction_memory = self.Memory()
		self.loader.instruction_size = {}



		print("begin of clemory backing")
		"""
		FILE FORMAT
		[INSTRUCTION ADDRESS][INSTRUCTION SIZE][INSTRUCTION BYTECODE]
		[       8 BYTE      ][      8 BYTE    ][     SIZE-BYTES     ]
		"""
		while True:
			curr = self._binary_stream.read(9)
			if (len(curr) == 0):
				break
			insaddr = struct.unpack("<Q", curr[0:8])[0]
			size = struct.unpack("<B", curr[8:9])[0]
			
			bytecode = self._binary_stream.read(size)
			
			try:
				self.memory.store(insaddr, bytecode)
			except:
				self.memory.add_backer(insaddr, b'\x90' * 0xff, overwrite = True)
				self.memory.store(insaddr, bytecode)




			self._add_instruction(insaddr, bytecode)
		print("end of clemory backing")
	def _add_instruction(self, instruction_address, bytecode):
		"""
		Adds a bytecode instruction to the Clememory of the project
		"""
		self.loader.instruction_memory.store_instruction(instruction_address, bytecode)

register_backend("dyninstruction", DynamicRecoveredInstructions)







		
