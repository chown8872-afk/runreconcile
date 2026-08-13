#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
python_bin=${PYTHON_BIN:-python3}
runreconcile_bin=${RUNRECONCILE_BIN:-runreconcile}
workspace=$(mktemp -d "${TMPDIR:-/tmp}/runreconcile-demo-workspace.XXXXXX")
private_dir=$(mktemp -d "${TMPDIR:-/tmp}/runreconcile-demo-private.XXXXXX")

cleanup() {
  if [ "${RUNRECONCILE_DEMO_KEEP:-0}" = "1" ]; then
    printf 'Demo workspace kept at: %s\n' "$workspace"
    printf 'Private demo data kept at: %s\n' "$private_dir"
    return
  fi

  "$python_bin" - "$workspace" "$private_dir" <<'PY'
import shutil
import sys

for target in sys.argv[1:]:
    shutil.rmtree(target)
PY
}
trap cleanup EXIT HUP INT TERM

cp "$repository_dir/examples/runreconcile.toml" "$workspace/runreconcile.toml"
cp "$repository_dir/examples/demo_job.py" "$workspace/demo_job.py"

"$runreconcile_bin" validate --contract "$workspace/runreconcile.toml"
snapshot_output=$(
  "$runreconcile_bin" snapshot \
    --contract "$workspace/runreconcile.toml" \
    --output "$private_dir/before.json" \
    --run-id demo-001
)
baseline_sha=$(
  printf '%s' "$snapshot_output" | "$python_bin" -c \
    'import json, sys; print(json.load(sys.stdin)["sha256"])'
)

"$python_bin" "$workspace/demo_job.py" --run-id demo-001
"$runreconcile_bin" verify \
  --contract "$workspace/runreconcile.toml" \
  --before "$private_dir/before.json" \
  --before-sha256 "$baseline_sha" \
  --output-dir "$workspace/receipt"

"$python_bin" - "$workspace/receipt" <<'PY'
import hashlib
import json
import pathlib
import sys

receipt_dir = pathlib.Path(sys.argv[1])
receipt_bytes = (receipt_dir / "receipt.json").read_bytes()
receipt = json.loads(receipt_bytes)
complete = json.loads((receipt_dir / "complete.json").read_text(encoding="utf-8"))

if receipt.get("verdict") != "ACCEPTED":
    raise SystemExit(f"demo verdict was {receipt.get('verdict')!r}, expected 'ACCEPTED'")
if receipt.get("summary") != {"errors": 0, "failed": 0, "passed": 3, "skipped": 0}:
    raise SystemExit(f"unexpected demo summary: {receipt.get('summary')!r}")
expected_digest = hashlib.sha256(receipt_bytes).hexdigest()
if complete != {"complete": True, "receipt_json_sha256": expected_digest}:
    raise SystemExit("completion marker does not match receipt.json")

print("Demo completed with ACCEPTED: 3 checks passed, 0 unexpected changes.")
PY
