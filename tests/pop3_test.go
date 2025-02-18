package tests_test

import (
	"testing"

	"github.com/foxcpp/maddy/tests"
)

func TestPOP3EndpointAuthMap(tt *testing.T) {
	tt.Parallel()
	t := tests.NewT(tt)

	t.DNS(nil)
	t.Port("pop3")
	t.Config(`
		storage.imapsql test_store {
			driver sqlite3
			dsn imapsql.db
		}

		pop3 tcp://127.0.0.1:{env:TEST_PORT_pop3} {
			tls off

			auth_map email_localpart
			auth pass_table static {
				entry "user" "bcrypt:$2a$10$E.AuCH3oYbaRrETXfXwc0.4jRAQBbanpZiCfudsJz9bHzLr/qj6ti" # password: 123
			}
			storage &test_store
		}
	`)
	t.Run(1)
	defer t.Close()

	pop3Conn := t.Conn("pop3")
	defer pop3Conn.Close()
	pop3Conn.ExpectPattern(`\+OK *`)
	pop3Conn.Writeln("USER user@example.org")
	pop3Conn.ExpectPattern(`\+OK *`)
	pop3Conn.Writeln("PASS 123")
	pop3Conn.ExpectPattern(`\+OK *`)
	pop3Conn.Writeln("STAT")
	pop3Conn.ExpectPattern(`\+OK *`)
}

func TestPOP3EndpointStorageMap(tt *testing.T) {
	tt.Parallel()
	t := tests.NewT(tt)

	t.DNS(nil)
	t.Port("pop3")
	t.Config(`
		storage.imapsql test_store {
			driver sqlite3
			dsn imapsql.db
		}

		pop3 tcp://127.0.0.1:{env:TEST_PORT_pop3} {
			tls off

			storage_map email_localpart

			auth_map email_localpart
			auth pass_table static {
				entry "user" "bcrypt:$2a$10$z9SvUwUjkY8wKOWd9IbISeEmbJua2cXRPqw7s2BnLXJuc6pIMPncK" # password: 123
			}
			storage &test_store
		}
	`)
	t.Run(1)
	defer t.Close()

	pop3Conn := t.Conn("pop3")
	defer pop3Conn.Close()
	pop3Conn.ExpectPattern(`\+OK *`)
	pop3Conn.Writeln("USER user@example.org")
	pop3Conn.ExpectPattern(`\+OK *`)
	pop3Conn.Writeln("PASS 123")
	pop3Conn.ExpectPattern(`\+OK *`)
	pop3Conn.Writeln("LIST")
	pop3Conn.ExpectPattern(`\+OK *`)
	pop3Conn.ExpectPattern(`\.`)

	pop3Conn2 := t.Conn("pop3")
	defer pop3Conn2.Close()
	pop3Conn2.ExpectPattern(`\+OK *`)
	pop3Conn2.Writeln("USER user@example.com")
	pop3Conn2.ExpectPattern(`\+OK *`)
	pop3Conn2.Writeln("PASS 123")
	pop3Conn2.ExpectPattern(`\+OK *`)
	pop3Conn2.Writeln("LIST")
	pop3Conn2.ExpectPattern(`\+OK *`)
	pop3Conn2.ExpectPattern(`\.`)
}
