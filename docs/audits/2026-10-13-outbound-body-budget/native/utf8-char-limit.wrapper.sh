#!/bin/sh
printf "owned child started\n" > /Users/<dev>/Desktop/arcora-perp/candidate-protocol-20261011/target/outbound-body-validation-20261013/recovery/owned-body-probe/utf8-char-limit.child-marker
exec /usr/bin/curl "$@"
