import angr
import logging
import IPython
logging.getLogger('angr').setLevel('INFO')
a = angr.project.load_trace('./bytecode.bin', 'x86_64')
b = a.analyses.CFGInstrace('./trace.json')
IPython.embed()
