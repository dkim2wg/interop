## 1. Email address angle brackets

It's not clear to me whether we expect the email addresses stored
in mf= and rt=, and the same addresses passed in via API, to be
surrounded with angle brackets or not.

## 2. RSA public key type

We've inherited the [uncertainty about public key format](https://www.rfc-editor.org/errata/eid3017)
for RSA keys from DKIM. That means we need to attempt to parse it
in both formats and use the one that works.

## 3. Retrieving i= / m= for error messages

If a Dkim2-Signature or Message-Instance header cannot be parsed then
we need to return an error. That error should contain the i=/m= to
identify which header, but we weren't able to parse it. I've added
fallback parsing to just look for the identifier tag when parsing
fails.

## 4. Error messages missing

spec-01 includes a set of standard error messages, but they don't
cover some error cases:

 - Duplicate i=/m= in header
 - Header doesn't contain i=/m=

## 5. Hash comparisons

Malicious input could cause non-canonical base64 encoded hashes,
so comparing hashes as base64 encoded text isn't safe. I'm
erroring out for non-canonical encoding (and comparing the
decoded binary rather than the text).

## 6. Identifying s=

During verification we need to modify the s= tag in the 
most recent Dkim2-Signature to blank out the signature.
To do that we need to find the s= tag.

A simple search for "s=" may fail, as "s=" could appear
in base64 encoded fields.

Searching for a regex `;\s*s=` looks more reasonable, as
semicolons don't appear in base64. But if s= is the first
tag in the header that'd fail.