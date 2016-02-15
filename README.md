# `stapled` - A OCSP stapling daemon

![Stapler](https://media.giphy.com/media/RQwkFm79MYuUU/giphy.gif)

> **Note:** This is still a work in progress, idk if I'd actually use it yet!

A caching OCSP daemon that makes stapling less painful. Inspired in
large part by the [notes](https://gist.github.com/sleevi/5efe9ef98961ecfb4da8)
written on the topic by Ryan Sleevi.

Intended to be easily proxyabe and distributable (and make life at
least somewhat easier for applications implementing OCSP stapling
in a less than ideal way).
