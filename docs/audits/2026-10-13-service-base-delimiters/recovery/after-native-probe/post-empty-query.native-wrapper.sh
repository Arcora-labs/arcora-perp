#!/bin/sh
printf "owned child started\n" > /Users/huseyinarslan/Desktop/arcora-perp/candidate-protocol-20261011/target/service-base-validation-20261013/recovery/after-native-probe/post-empty-query.child-marker
exec /usr/bin/curl "$@"
