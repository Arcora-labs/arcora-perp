#!/bin/sh
printf "%s\n" "$$" > /Users/huseyinarslan/Desktop/arcora-perp/candidate-protocol-20261011/target/bearer-argv-validation-20261013/native/curl-timeout.owned-pid
printf "%s\0" "$@" > /Users/huseyinarslan/Desktop/arcora-perp/candidate-protocol-20261011/target/bearer-argv-validation-20261013/native/curl-timeout.argv.bin
exec /usr/bin/curl "$@"
