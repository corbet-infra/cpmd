#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-or-later
# Unit test of roles/debloat/files/own-procs.py on the controller: a renamed copy of sleep stands in for dockerd.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../../roles/debloat/files/own-procs.py"
d=$(mktemp -d)
trap 'find "$d" -mindepth 1 -delete; rmdir "$d"' EXIT
cp "$(command -v sleep)" "$d/fakedockerd"
"$d/fakedockerd" 300 &
pid=$!
sleep 1
out=$(python3 -I "$script" stop --dry-run --match 'comm=^fakedockerd$')
echo "$out" | grep -q "\"pid\": $pid" || { echo "FAIL dry run did not match"; exit 1; }
kill -0 "$pid" || { echo "FAIL dry run killed it"; exit 1; }
out=$(python3 -I "$script" stop --match 'comm=^fakedockerd$')
echo "$out" | grep -q "\"terminated\": \[$pid\]" || { echo "FAIL not terminated: $out"; exit 1; }
wait "$pid" 2>/dev/null || true
if kill -0 "$pid" 2>/dev/null; then echo "FAIL still alive"; exit 1; fi
# nothing matches the second time: idempotent
out=$(python3 -I "$script" stop --match 'comm=^fakedockerd$')
echo "$out" | grep -q '"matched": \[\]' || { echo "FAIL second run matched"; exit 1; }
# a pattern that matches the test itself must not kill its own ancestors
out=$(python3 -I "$script" stop --dry-run --match 'args=test-own-procs')
echo "$out" | grep -q "\"pid\": $$" && { echo "FAIL matched an ancestor"; exit 1; }
echo "own-procs OK"
