#!/bin/bash
# usage: ./run.sh <label> <command...>
LABEL="$1"; shift
LOG=~/ztgw/attacks/labels.csv
[ -f "$LOG" ] || echo "label,start,end" > "$LOG"
START=$(date +%s)
echo ">>> $LABEL starting at $START"
"$@"
END=$(date +%s)
echo "$LABEL,$START,$END" >> "$LOG"
echo "<<< $LABEL done ($((END-START))s)"
echo "--- 60s cooldown ---"
sleep 60
