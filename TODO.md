* Write a whole bunch of tests!
* Way more logging
* Stats!
  * would be nice to have some kind of window into what is currently
    in the cache (prob via another http interface?)
* Refactor definition parsing section of `cmd/stapled.go`
* Allow per definition `proxy`/`upstream-stapleds`
* Polish definition format...
* Implement parsing certificates from defined folder
* Implement removing items from the cache
* Implement certificate folder watching to add new entries to the cache
* Need to validate the the `verifyResponse` method is working as intended
* Rework death on stale responses logic -- current impl. is not ideal (or doing
  what was intended)
* Issuers should be cached and lookup-able somewhere so we don't need to download
  them multiple times if they aren't available on disk
* Write configuration documentation!
