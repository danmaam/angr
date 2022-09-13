from cle import Backend, register_backend
from cle.errors import CLEError
import logging
import struct
from collections import defaultdict

l = logging.getLogger(name=__name__)

__all__ = ('DynamicRecoveredInstructions',)

class DynamicRecoveredInstructions(Backend):
    """
    Representation of the instruction trace of a binary obtained after 
    dynamic execution of the binary (e.g. Intel PIN, Valgrind)
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        #TODO: determine instruction size from opcode
        #load into memory 
        self.loader._instruction_map = defaultdict(dict)
        """
        FILE FORMAT
        [INSTRUCTION ADDRESS][TIMESTAMP][INSTRUCTION SIZE][INSTRUCTION BYTECODE]
        [       8 BYTE      ][  8 BYTE ][      8 BYTE    ][     SIZE-BYTES     ]
        """
        while True:
            curr = self._binary_stream.read(24)
            if (len(curr) == 0):
                break
            insaddr = struct.unpack("<Q", curr[0:8])[0]
            timestamp = struct.unpack("<Q", curr[8:16])[0]
            size = struct.unpack("<Q", curr[16:24])[0]

            bytecode = self._binary_stream.read(size)

            self._add_instruction(insaddr, bytecode, timestamp)

    def _add_instruction(self, instruction_address, bytecode, timestamp):
        """
        Adds a bytecode instruction to the Clememory of the project
        """
        self.loader._instruction_map[instruction_address][timestamp] = bytecode

register_backend("dyninstruction", DynamicRecoveredInstructions)







        
