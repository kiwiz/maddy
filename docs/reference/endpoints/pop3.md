# POP3 endpoint

Module 'pop3' is a listener that implements the POP3 protocol and provides access to local message storage specified by the 'storage' directive.

## Configuration directives

```
pop3 tcp://0.0.0.0:110 tls://0.0.0.0:995 {
    tls /etc/ssl/private/cert.pem /etc/ssl/private/pkey.key
    io_debug no
    debug no
    insecure_auth no
    auth pam
    storage &local_mailboxes
}
```

### tls _certificate-path_ _key-path_ { ... }
Default: global directive value

TLS certificate & key to use. Fine-tuning of other TLS properties is possible by specifying a configuration block and options inside it:

```
tls cert.crt key.key {
    protocols tls1.2 tls1.3
}
```

See [TLS configuration / Server](/reference/tls/#server-side) for details.

---

### proxy_protocol _trusted ips..._ { ... }
Default: not enabled

Enable use of HAProxy PROXY protocol. Supports both v1 and v2 protocols.
If a list of trusted IP addresses or subnets is provided, only connections
from those will be trusted.

TLS for the channel between the proxies and maddy can be configured
using a 'tls' directive:
```
proxy_protocol {
    trust 127.0.0.1 ::1 192.168.0.1/24
    tls &proxy_tls
}
```
Note that the top-level 'tls' directive is not inherited here. If you
need TLS on top of the PROXY protocol, securing the protocol header,
you must declare TLS explicitly.

---

### io_debug _boolean_
Default: `no`

Write all commands and responses to stderr.

---

### io_errors _boolean_
Default: `no`

Log I/O errors.

---

### debug _boolean_
Default: global directive value

Enable verbose logging.

---

### insecure_auth _boolean_
Default: `no` (`yes` if TLS is disabled)

Allow plain-text authentication over unencrypted connections.

---

### auth _module-reference_
**Required.**

Use the specified module for authentication.

---

### storage _module-reference_
**Required.**

Use the specified module for message storage.

