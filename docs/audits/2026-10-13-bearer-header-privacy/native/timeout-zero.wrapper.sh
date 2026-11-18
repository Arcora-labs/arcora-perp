#!/bin/sh
printf "%s\n" "$$" > /Users/<dev>/Desktop/arcora-perp/candidate-protocol-20261011/target/bearer-argv-validation-20261013/native/timeout-zero.owned-pid
printf "%s\0" "$@" > /Users/<dev>/Desktop/arcora-perp/candidate-protocol-20261011/target/bearer-argv-validation-20261013/native/timeout-zero.argv.bin
exec /usr/bin/curl "$@"
