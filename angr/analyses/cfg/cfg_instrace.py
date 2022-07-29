from dis import Instruction
from .cfg_base import CFGBase
from ..forward_analysis import ForwardAnalysis
import capstone
import struct


class InstructionDump:
  def __init__(self, buffer):
    self.buffer = buffer
    self.len = len(buffer)
    self.read_bytes = 0

  def next_instruction(self):
    if (self.read_bytes < self.len):
      curr_instruction = self.buffer[self.read_bytes:self.read_bytes + 24]
      self.read_bytes += 24

      address = struct.unpack('<Q', curr_instruction[0:8])[0]
      timestamp = struct.unpack('<Q', curr_instruction[8:16])[0]
      size = struct.unpack('<Q', curr_instruction[16:24])[0]

      bytecode = self.buffer[self.read_bytes:self.read_bytes+size]
      self.read_bytes += size

      md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
      dis = list(md.disasm(bytecode, 0))[0]

      return dis

    else:
      return False


class CFGInstrace(ForwardAnalysis, CFGBase):
  """
  The CFG is recovered from a list of executed instructions, and a trace
  of execution, one per thread
  """
  tag = 'CFGInstrace'

  def __init__(self, instructions, normalize=False, base_state=None, detect_tail_calls=False, low_priority=False, model=None):
    ForwardAnalysis.__init__(self, allow_merging=False)
    CFGBase.__init__(
      self,
      'instrace',
      0,
      normalize=normalize,
      binary=None,
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

    # We need to load the instructions from the received trace
    ins_trace = InstructionDump(instructions)
    while True:
      x = ins_trace.next_instruction()
      if x == False:
        break
      else:
        print("0x%x:\t%s\t%s" %(x.address, x.mnemonic, x.op_str))