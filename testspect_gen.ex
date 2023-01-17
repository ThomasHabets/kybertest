#!/usr/bin/env expect

set args [lrange $argv 0 end]

spawn bash -c [lrange $argv 0 end]

#spawn $args
expect "Private key password"
send "secret\r"
expect "Again:"
send "secret\r"
expect EOF
lassign [wait] pid spawnid os_error_flag value
if {$value != 0} {
    exit $value
}
