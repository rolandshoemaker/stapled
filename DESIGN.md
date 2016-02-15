# Design

`stapled` is composed of two basic components, a in-memory
(and on disk) self-updating OCSP response cache and a OCSP
responder that reads from this cache.

## Cache

The cache contains a `map` which acts as a lookup table,
containing the SHA256 hashes of each possible request which
map to the pointer of the entry being requested (one for
each of the four possible hashing algorithms).

```
    Insert
    ------


                                   OCSP hash     Hash
                                   algorithm    request            Lookup table

                                  +-+sha1+------+sha256+----+688787d8ff144c502c7f5cffaafe2cc5...+-+
                                  |                          ...                                  |
                                  +-+sha256+----+sha256+----+2878769bea4d42bbce398959fdbf8b11...+-+
 Issuer Name, Issuer PK, Serial --+                          ...                                  +-----+ Entry
                                  +-+sha384+----+sha256+----+dbf8b11530aa895f2f28317c4261c225...+-+
                                  |                          ...                                  |
                                  +-+sha512+----+sha256-----+2a760e8616b0d8191efd1f5a7441d554...+-+






    Lookup
    ------



                 Hash
                request            Lookup table

 OCSP request --+sha256+----+688787d8ff144c502c7f5cffaafe2cc5...+---+ Entry

```

Both the lookup table and entries are protected by RW locks in
order to protect from dirty reads/writes during a response/update.

An entry can only be added to the cache if they contain a
currently valid OCSP response. After being added the entry
is checked at a configurable interval for freshness. Once
it enters a specific window a time in the future will be
randomly selected and the upstream OCSP responder will be
contacted. If a new response is received the entry will be
updated otherwise the process is repeated (more detail
bellow).

### Choosing when to refresh

## Proxying / Distributed

`stapled` is easily proxyable and acts as a RFC compliant
OCSP responder allowing instances to speak to upstream
instances instead of fetching OCSP requests directly itself
if wanted.

```

+-----------+   +-----------+
|   OCSP    |   |   OCSP    |
| responder |   | responder |
+-----+-----+   +----+------+
      |              |
      |              |
      |              |
  +---+---+      +---+-----+   +-----------+   +-----------+
  | proxy +------+ stapled |   |   OCSP    |   |   OCSP    |
  +-------+      +-----+---+   | responder |   | responder |
                       |       +-+---------+   +---+-------+
                       +---+     |                 |
                           |     |                 |
                           |     +-----------------+
                           |     |
       +--------+        +-+-----+-+      +-------+
       | Apache +--http--+ stapled +--fs--+ nginx |
       +--------+        +---------+      +-------+

```
