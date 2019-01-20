## Pwnpass
Pwnpass is a Go API to query how many instances of a certain password have been
seen by haveibeenpwned.com.

To use, simply pass a SHA1 hash.Hash to pwnpass.Match() and it will return the number
of times that hash has been seen.