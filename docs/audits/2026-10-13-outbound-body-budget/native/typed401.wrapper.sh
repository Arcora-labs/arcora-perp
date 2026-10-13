#!/bin/sh
printf "owned child started\n" > /Users/huseyinarslan/Desktop/arcora-perp/candidate-protocol-20261011/target/outbound-body-validation-20261013/recovery/owned-body-probe/typed401.child-marker
exec /usr/bin/curl "$@"
