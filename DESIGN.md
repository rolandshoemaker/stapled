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
 Issuer Name         +-+sha256+----+sha256+----+2878769bea4d42bbce398959fdbf8b11...+-+
 Issuer Public Key --+                          ...                                  +-----+ Entry
 Serial              +-+sha384+----+sha256+----+dbf8b11530aa895f2f28317c4261c225...+-+
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

### Initialization

Entries can be added to the cache in three ways

1. from definitions in the configuration file
2. from certificates in a watched directory
3. from passing requests to upstream responders/`stapled`s

Currently this is extremely messy and needs to be better
thought through. Some code is duplicated/located outside
where it probably should.

### Choosing when to refresh

After a entry is added to the cache it is checked using the
algorithm outlined below at a configurable interval to decide
whether a upstream source should be contacted to check for a new
response.

> Largely based on Microsoft's [CryptoAPI pre-fetching behaviour](https://technet.microsoft.com/en-us/library/ee619723(v=ws.10).aspx)

Variables:
* `LastSync` - last time response was fetched
* `ThisUpdate`
* `NextUpdate`
* (if available) `NextPublish` - optional OCSP extension
* (if available) `max-age` - cache property

1. If now is after `NextUpdate` refresh response
2. If `max-age` is more than zero and now is after `LastSync + max-age`
   refresh response
3. If now is after `(NextUpdate - ThisUpdate) / 4`, or `NextPublish`,
   randomly select a a time between then and `NextUpdate`
4. If the time is before now refresh the response

### On-Disk cache

If `cache-folder` is set the in-memory cache will be mirrored
on disk (one-way). These responses can also be used to seed
the cache on initial start-up.

When a entry in the cache is updated and the response changes
it will be written to a temporary file next to the existing
response file and then renamed to overwrite it. This should
be *atomic-ish* on most operating systems.

1. Write `example.ocsp.tmp`
2. Rename `example.ocsp.tmp` to `example.ocsp`

## Interaction

```

                  +-----------+
                  |   OCSP    |
                  | responder |
                  +-----+-----+
                        |
                        |
                        |
 +--------+        +----+----+      +-------+
 | Apache +--http--+ stapled +--fs--+ nginx |
 +--------+        +---------+      +-------+

```

### HTTP responder

`stapled` acts as a RFC 2560 compliant OCSP responder which
reads responses from the cache. The Issuer name and public
key hashes and serial are extracted from requests and hashed
to use as the key in the lookup table.

### Proxying / Distribution

Since `stapled` acts as both a OCSP client and responder it can be
easily chained simply by specifying another instance as the upstream
responder for a cache entry. Thanks to support in `net/http` `stapled`
can also easily proxy connections to upstream responders, or other
instances.

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
                         +-+-----+-+
                         | stapled |
                         +---------+

```
