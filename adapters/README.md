# EMET adapters

Optional, out-of-core integrations. The minimal-TCB guarantee (SPEC section 10)
applies to membrane / organs / monitor ONLY, never to anything in this directory.

Adapters EMIT DATA. They never sign, enforce, upload, or actuate -- the operator
does that downstream (SPEC boundaries 5 and 6). An adapter that signed, blocked,
or wrote to a transparency log would breach EMET. EMET attests; the operator acts.
