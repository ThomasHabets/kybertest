#!/usr/bin/env expect

spawn {*}$argv
proc loopy {} {
    while {1} {
	expect {
	    -re "Private key password:|enter AES-256-CBC decryption password:|Again:" {
		send "secret\r"
		expect -ex "\n"
	    }
	    timeout {
		puts "Done"
		return
	    }
	}
    }
}
catch {loopy} {}
lassign [wait] pid spawnid os_error_flag value
if {$value != 0} {
    exit $value
}
