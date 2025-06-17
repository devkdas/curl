---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: quic-v2
Help: Use QUIC version 2 only for HTTP/3 connections
Protocols: HTTP
Category: http important tls
Added: 8.X.Y
See-also:
  - http3
  - http-version
---
# NAME

--quic-v2 - Use QUIC version 2 only for HTTP/3

# SYNOPSIS

`--quic-v2`

# DESCRIPTION

This option tells curl to attempt to connect to the server using exclusively
QUIC version 2. QUIC version 2 is identified by the protocol ID `0x6b3343cf`.

If this option is used, curl will only try to establish a QUIC version 2
connection. It will not fall back to other QUIC versions (like v1) or other
HTTP versions (like HTTP/2 or HTTP/1.1) if the QUIC v2 connection attempt
fails or is not supported by the server. This behavior is similar to
`--http3-only` but specifically targets QUIC version 2 for the QUIC layer.

This option requires a QUIC backend library (e.g., ngtcp2, quiche, OpenSSL
with QUIC support) that is capable of and configured to use QUIC version 2.
If the backend does not support QUIC v2 or cannot be configured for it, using
this flag might result in a connection failure or the flag having no specific
effect on the QUIC version chosen (depending on the backend).
