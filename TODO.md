* Write a whole bunch of tests!
* Refactor definition parsing section of `cmd/stapled.go`
* Allow per definition `proxy`/`upstream-stapleds`
* Polish definition format...
* Seed responses from disk if cache-folder is provided
* Keep cache entries in sync with on disk cache (one-way)
* Implement parsing certificates from defined folder
* Implement certificate folder watching to add new entries
  to the cache
* Need to validate the the `verifyResponse` method is working
  as intended
* Rework death on stale responses logic -- current impl.
  is not ideal

* Write configuration documentation!
