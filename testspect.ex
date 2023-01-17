#!/usr/bin/env expect

set bin [lindex $argv 0]
set key [lindex $argv 1]
set file [lindex $argv 2]

spawn $bin -k $key -f $file
expect {
    -re "Private key password:|enter AES-256-CBC decryption password:" {
	send "secret\r"
	expect -ex "\n"
	expect EOF
    }
    EOF
}
lassign [wait] pid spawnid os_error_flag value
if {$value != 0} {
    exit $value
}
set payload $expect_out(buffer)

spawn cat testdata/plain.txt
expect EOF
set golden $expect_out(buffer)

if {$payload != $golden} {
    puts "=== Payload mismatch ==="
    puts "<$payload>"
    puts "<$golden>"
    exit 1
}
