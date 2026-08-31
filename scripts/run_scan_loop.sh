#!/bin/sh
# Restart the resumable scanner until the frame is exhausted (max 40 restarts).
cd "$(dirname "$0")/.." || exit 1
i=0
while [ $i -lt 40 ]; do
  python3 scripts/scan.py --all --workers 6 >> data/scan.log 2>&1
  todo=$(python3 -c "
import json
frame={json.loads(l)['full_name'] for l in open('data/frame.jsonl')}
done={json.loads(l)['full_name'] for l in open('data/results.jsonl')}
print(len(frame-done))")
  echo "loop $i: remaining $todo" >> data/scan.log
  [ "$todo" -eq 0 ] && break
  i=$((i+1)); sleep 5
done
