#!/bin/sh
printf "%s\n" "$$" > /Users/huseyinarslan/Desktop/arcora-perp/candidate-protocol-20261011/target/bearer-argv-validation-20261013/native/supervisor-hang.owned-pid
printf "%s\0" "$@" > /Users/huseyinarslan/Desktop/arcora-perp/candidate-protocol-20261011/target/bearer-argv-validation-20261013/native/supervisor-hang.argv.bin
exec /opt/homebrew/bin/python3.12 -c 'import time;time.sleep(30)' "$@"
