#!/bin/sh
printf "%s\n" "$$" > /Users/<dev>/Desktop/arcora-perp/candidate-protocol-20261011/target/bearer-argv-validation-20261013/native/endpoint-query.owned-pid
printf "%s\0" "$@" > /Users/<dev>/Desktop/arcora-perp/candidate-protocol-20261011/target/bearer-argv-validation-20261013/native/endpoint-query.argv.bin
exec /usr/bin/curl "$@"
