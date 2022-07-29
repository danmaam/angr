from collections import defaultdict
from dis import Instruction
from typing import Dict
from .cfg_base import CFGBase
from ..forward_analysis import ForwardAnalysis
from ..analysis import AnalysesHub
import capstone
import struct
import logging

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

    self._instructions = defaultdict(dict)

    discovered_instructions = self.project.loader._main_binary_stream
    self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    while True:
      curr = discovered_instructions.read(24)
      if (len(curr) == 0):
        break
      insaddr = struct.unpack("<Q", curr[0:8])
      timestamp = struct.unpack("<Q", curr[8:16])
      size = struct.unpack("<Q", curr[16:24])

      bytecode = discovered_instructions.read(size)
      self._add_instruction(insaddr, timestamp, bytecode)

    # We need to load the instructions from the received trace
    if isinstance(trace, str):
      with open(trace, "rb") as f:
       pass 



        
  def _add_instruction(self, address, timestamp, bytecode):
    i = list(self._md.disasm(bytecode, 0x1000))[0]
    print("Added " + "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    self._instructions[address][timestamp] = bytecode


AnalysesHub.register_default('CFGInstrace', CFGInstrace)