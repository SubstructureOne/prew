# Prew

Prew is a reverse rewrite proxy for PostgreSQL (other protocol support 
pending). It generalizes rewrite rules into:

* A parser
* A filter
* A transformer
* An encoder
* A reporter

A sample binary is included but it is primarily intended to be pulled in as 
a library and provided custom components for the rewrite rules.

Packets returned from the service being proxied are currently not subject to
any rules and are always passed back to the client unmodified.

## Proxy Components

### Parser

The parser is responsible for parsing a packet into a standard struct, that 
will be used for the following rules.

### Filter

The filter can selectively filter out packets. No response is sent for 
filtered packets.

### Transformer

The transformer can optionally modify packet content (i.e., the rewrite step).

### Encoder

The encoder encodes the transformed packet back into its raw format (skipped 
if no transformation was made).

### Reporter

The reporter runs concurrently to provide logging or additional 
side-functionality based on the content of the packet.

# Attributions

Prew is based in large part upon 
[sql-proxy-rs](https://github.com/ryscheng/sql-proxy-rs) 
by [Raymond Cheng](https://github.com/ryscheng).
