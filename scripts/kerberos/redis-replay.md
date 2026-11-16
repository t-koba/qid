# Redis local-AOF replay qualification

Run `python3 scripts/kerberos/test-redis-replay.py` with Cargo, Python 3 and a
local Docker daemon. The `redis-replay-qualification` job in `kerberos-mit.yml`
runs this harness independently of the existing MIT SPNEGO proof. It uses the
exact Redis **7.2.4** release (`redis:7.2.4-bookworm`, BSD licensed), not a
production service or a recommended deployment version.

`RedisCache::set_if_absent_wait_aof` is separate from `SharedCache` semantics.
It holds one connection lock across `SET NX EX` and, only for a new key,
`WAITAOF 1 0 <timeout-ms>`. Only a two-integer reply with local count exactly
one and a nonnegative replica count succeeds. A duplicate returns false;
unsupported commands, disabled AOF, errors, timeouts without the local ack,
and malformed replies fail closed with opaque errors. An uncertain write is
never deleted. The explicit nonzero timeout is a caller choice, not a generic
cache default; the fixture uses 2000 ms. This bounds the Redis wait, **not** a
stalled transport; the harness separately kills stalled test processes after
20 seconds.

The only Kerberos adapter is in the ignored integration test. Eight independent
Redis connections contend for one replay tag, with exactly one acknowledged
winner. With AOF enabled, `appendfsync everysec`, RDB snapshots disabled, and
AOF rewriting disabled, the harness sends SIGKILL to Redis and starts the same
container with its existing data volume. New acceptor connections must reject
the retained tag and accept a fresh tag. Separate disposable instances require
failure with AOF disabled and with `WAITAOF` renamed away (an unavailable-command
simulation, not an older-Redis interoperability test). The lightweight RESP
contract test also covers short, malformed, truncated and insufficient replies.

Containers publish only ephemeral loopback ports. Commands, Redis logs, URLs,
and replay tags are not printed. The harness removes its containers and
anonymous volumes in `finally`, including on test failure or interruption.
Runtime settings exist only in this test harness. No provider configuration,
routes, production backend selection, or MIT checks are changed.

This is a **single-server process-crash retention candidate**, not proof of
multi-host failover durability, disk/power-loss safety, replica persistence,
full AP-REQ acceptor correctness, or any production deployment guarantee. A
passing CI run is required to establish the real Redis restart result; the
in-process RESP peer alone cannot establish it.
