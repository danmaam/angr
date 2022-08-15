import angr
import logging
import IPython
logging.getLogger('angr').setLevel('INFO')
a = angr.project.load_trace('../MScThesis/Tests/bytecode.bin', 'x86_64')
b = a.analyses.CFGInstrace('../MScThesis/Tests/trace.json')
IPython.embed()
