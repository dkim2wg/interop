# dkim2
DKIM2 library and tools

## Tests

Run `go test . -count=1 -v` to run library test and interop tests
(parsing expected results from python and brong).

Our signed messages are in stevea/testdata/golden/expected.

## Status

The library seems to generate and parse messages correctly.

The CLI tools are not ready for use.

## Missing

Validation of MAIL FROM / RCPT TO chains.

Results of message-instance recipes that return a "we
can't reconstruct this" result.
