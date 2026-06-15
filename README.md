# grpc-edge-router

A generic, multiplexing gateway that lets a central cloud service issue gRPC
calls **into** edge machines that sit behind NAT/firewalls and can never be
dialed directly. Edges dial **out** over a reverse SSH tunnel; the gateway routes
each inbound gRPC call to the right edge by a `x-client-id` metadata header.

The gateway is **proto-agnostic**: it forwards arbitrary gRPC services and
methods as opaque bytes, with no knowledge of any `.proto`. Add or change edge
services without ever touching or redeploying the gateway.

```
  edge dials out                ┌──────────────── grpc-edge-router (one process) ──────────────┐
  ssh -R 0:localhost:50051      │  SSH ingress (Apache MINA SSHD)                               │
   ───────────────────────────▶ │    • pubkey auth -> clientId                                  │
                                │    • reverse-forward -> bind 127.0.0.1:<dynamic port>         │
                                │    • capture bound port -> EdgeRegistry.put(clientId, port)   │
                                │                                                               │
  caller gRPC                   │   EdgeRegistry: clientId -> { ssh session, port, channel }    │
  x-client-id: clientA          │                         ▲                ▲                    │
   ───────────────────────────▶ │  gRPC passthrough proxy ─┘ (route by     │                    │
                                │    x-client-id) ── ManagedChannel ──▶ 127.0.0.1:port ─────────┼──┐
  ListClients()                 │  ClientDirectory gRPC ──reads EdgeRegistry┘                   │  │
   ───────────────────────────▶ └───────────────────────────────────────────────────────────────┘  │
                                                                          reverse SSH tunnel         │
                                                              edge's local gRPC server  ◀────────────┘
                                                                   (127.0.0.1:50051)
```

One SSH port, one gRPC port. N edges behind it, keyed by `clientId`. The
per-edge loopback port is an internal detail.

## How it works

- **Edges dial out** over SSH and request a reverse forward (`-R`) of their local
  gRPC port. The gateway authenticates the edge by its SSH public key, maps it to
  a `clientId`, and binds the forward to a **dynamic loopback port**.
- The gateway records `clientId -> 127.0.0.1:<port>` in an in-memory
  `EdgeRegistry` and caches a gRPC `ManagedChannel` to it.
- A **caller** opens a gRPC channel to the gateway and tags every call with
  `x-client-id: <clientId>` metadata. The gateway's generic passthrough proxy
  reads that header, looks up the edge's channel, and bridges the call — messages,
  headers, trailers, status, deadline, and flow control — in both directions.
- The **ClientDirectory** service (`ListClients` / `WatchClients`) lets callers
  discover which edges are currently connected.

## The routing contract

Every RPC from a caller must carry metadata **`x-client-id: <clientId>`**. A small
client interceptor makes this invisible:

```java
ManagedChannel channelFor(String clientId) {
  return ManagedChannelBuilder.forAddress(GATEWAY_HOST, GATEWAY_PORT)
      .usePlaintext() // TLS in production
      .intercept(new ClientInterceptor() {
        @Override
        public <Q, A> ClientCall<Q, A> interceptCall(
            MethodDescriptor<Q, A> method, CallOptions options, Channel next) {
          return new ForwardingClientCall.SimpleForwardingClientCall<>(next.newCall(method, options)) {
            @Override
            public void start(Listener<A> listener, Metadata headers) {
              headers.put(Metadata.Key.of("x-client-id", Metadata.ASCII_STRING_MARSHALLER), clientId);
              super.start(listener, headers);
            }
          };
        }
      })
      .build();
}

// usage: PortalControllerServiceGrpc.newBlockingStub(channelFor("clientA"))
```

The caller and the edge share the service `.proto`, as always. The gateway stays
proto-agnostic forever.

If `x-client-id` is missing the gateway returns `INVALID_ARGUMENT`; if no edge is
connected for that id it returns `UNAVAILABLE`.

## Running the gateway

Requires JDK 21.

```sh
# Provision authorized edge keys (see config/authorized_edges.example):
cp config/authorized_edges.example config/authorized_edges
# ...add your edges' public keys, each prefixed with its clientId...

./gradlew run
```

Configuration via environment variables (all optional):

| Variable | Default | Meaning |
|---|---|---|
| `GRPC_PORT` | `50000` | gRPC proxy + directory port |
| `SSH_HOST` | `0.0.0.0` | SSH ingress bind host |
| `SSH_PORT` | `2222` | SSH ingress port |
| `HOST_KEY_PATH` | `data/ssh_host_key.ser` | SSH host key (generated on first run) |
| `AUTHORIZED_EDGES_PATH` | `config/authorized_edges` | edge public-key → clientId file |

## Edge-side setup

The edge runs its normal gRPC server on loopback and dials out. `autossh` keeps
the tunnel alive across NAT timeouts and reconnects:

```sh
# Edge: gRPC server on 127.0.0.1:50051; reverse-forward it to the gateway.
autossh -M 0 -N \
  -R 0:localhost:50051 \                        # 0 = gateway assigns a dynamic port
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes \
  clientA@gateway.example.com -p 2222
```

- One SSH keypair **per edge**; the gateway maps the public key → `clientId` via
  `config/authorized_edges`. That mapping is the identity and revocation point.
- On reconnect the edge gets a **new** dynamic port; the registry updates and the
  old entry is evicted.
- The gateway only permits **reverse (`-R`) forwarding bound to loopback** — no
  shell, no command, no local (`-L`) forwarding, no agent/X11. Forwards are pinned
  to `127.0.0.1` server-side regardless of the requested bind address.

## Building and testing

```sh
./gradlew build                 # compile + test
./gradlew test                  # tests only
./gradlew test -DshowStd=true   # tests with gateway logs on stdout
```

The end-to-end test (`EndToEndTunnelTest`) stands up a real loopback "edge" gRPC
server, reverse-tunnels it into the gateway over SSH, and drives unary and
server-streaming calls through the generic passthrough — proving the gateway
needs no knowledge of the edge's proto.

## Project layout

```
proto/directory.proto                         # ClientDirectory API (gateway's own control plane)
src/main/java/io/github/nhwalker/edgerouter/
  Main.java                                   # wires SSH + gRPC proxy + directory over one registry
  EdgeRegistry.java                           # clientId -> { session, loopback port, ManagedChannel }
  SshIngress.java                             # MINA SSHD: pubkey->clientId, loopback reverse-forward capture
  GrpcPassthrough.java                        # generic byte proxy (fallback registry + ServerCall/ClientCall bridge)
  DirectoryService.java                       # ClientDirectory gRPC impl
  AuthorizedEdges.java                        # pubkey fingerprint -> clientId
src/test/java/...                             # registry/auth unit tests + end-to-end tunnel test
```

## Design notes & scope

- **Single replica, in-memory registry.** Sufficient for hundreds to low
  thousands of edges. Raise the process `ulimit -n` to cover persistent SSH +
  gRPC connections.
- **HA / multi-replica is deferred.** A given edge's tunnel terminates on one
  replica, so scaling out needs a shared directory (`clientId -> replica`) and
  sticky routing of `x-client-id`. The `EdgeRegistry` is the seam for that.
- **Keepalives** matter on three layers — the gRPC server permits keepalives, the
  edge's `autossh`/`ServerAliveInterval`, and MINA's idle timeout — all kept below
  NAT idle timeouts.

### Open security items (not yet implemented)

- **TLS / mTLS** on the exposed gRPC port. Today the caller↔gateway hop is
  plaintext; the edge↔gateway hop is already SSH-encrypted.
- **Caller authorization.** SSH keys authenticate *edges into* the gateway; there
  is not yet a control on *who may call out through* it or which `clientId` a
  caller may target. A caller can currently set any `x-client-id`. This must be
  added (e.g. mTLS client identity → allowed clientIds) before exposing the
  gateway to untrusted callers.
- **Host key & edge key management:** provisioning, rotation, revocation.

These are tracked as the next steps, consistent with the original design's
deferred items.
