typecheck.cmo: var.cmi type.cmi ssa.cmo pp.cmo debug.cmi \
    big_int_convenience.cmo \
    /root/whitebox_fuzzer/ocaml/../zarith/big_int_Z.cmi ast.cmo typecheck.cmi
typecheck.cmx: var.cmx type.cmx ssa.cmx pp.cmx debug.cmx \
    big_int_convenience.cmx \
    /root/whitebox_fuzzer/ocaml/../zarith/big_int_Z.cmx ast.cmx typecheck.cmi
