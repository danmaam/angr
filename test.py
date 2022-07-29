import angr
import logging
logging.getLogger('angr').setLevel('INFO')
a = angr.project.load_trace('../MScThesis/MScThesis/Tests/bytecode.bin', 'x86_64')
b = a.analyses.CFGInstrace('../MScThesis/MScThesis/Tests/trace.json')
