#!/usr/bin/env bash
# capture.sh OUTFILE CMD... : run CMD, write its stdout to OUTFILE (and echo it for the step log), keep the exit code.
out=$1; shift
"$@" >"$out"
rc=$?
cat "$out"
exit $rc
