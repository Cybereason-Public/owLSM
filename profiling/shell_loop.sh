#!/bin/bash
# One bash process, ten iterations a second, until the finish file appears.
finish="$1"
if [[ -z "$finish" ]]; then
    echo "usage: shell_loop.sh FINISH_FILE" >&2
    exit 2
fi

while [[ ! -e "$finish" ]]; do
    /bin/true
    sleep 0.1
done
