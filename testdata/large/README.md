# Large File Test Fixtures

This directory is for large binary files used in performance testing.
These files are not checked into version control due to size.

Generate test files locally with:
```
dd if=/dev/urandom of=testdata/large/random-1mb.bin bs=1M count=1
dd if=/dev/urandom of=testdata/large/random-10mb.bin bs=1M count=10
```
