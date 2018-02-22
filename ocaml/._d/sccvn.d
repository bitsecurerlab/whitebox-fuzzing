sccvn.cmo: var.cmi type.cmi ssa_visitor.cmi ssa.cmo pp.cmo dominator.cmo \
    debug.cmi cfg.cmi big_int_convenience.cmo \
    /root/whitebox_fuzzer/ocaml/../zarith/big_int_Z.cmi \
    /root/whitebox_fuzzer/ocaml/../batteries/_build/src/batString.cmi \
    BatListFull.cmo arithmetic.cmo sccvn.cmi
sccvn.cmx: var.cmx type.cmx ssa_visitor.cmx ssa.cmx pp.cmx dominator.cmx \
    debug.cmx cfg.cmx big_int_convenience.cmx \
    /root/whitebox_fuzzer/ocaml/../zarith/big_int_Z.cmx \
    /root/whitebox_fuzzer/ocaml/../batteries/_build/src/batString.cmx \
    BatListFull.cmx arithmetic.cmx sccvn.cmi
