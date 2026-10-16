---
title: DomainKeys Identified Mail Signatures v2 (DKIM2)
abbrev: DKIM2 Signatures
docname: draft-ietf-dkim-dkim2-spec-01
submissionType: IETF
number:
date:
v:
category: std
updates:
ipr: trust200902
keyword: Internet-Draft
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: R. Clayton
    name: Richard Clayton
    org: Yahoo
    email: rclayton@yahooinc.com
 -
    ins: W. Chuang
    name: Wei Chuang
    org: Google
    email: weihaw@google.com
 -
    ins: B. Gondwana
    name: Bron Gondwana
    org: Fastmail Pty Ltd
    street: Level 2, 114 William Street
    code: 3000
    country: Australia
    phone: "+61 457 416 436"
    email: brong@fastmailteam.com

normative:
    RFC1034:
    RFC2045:
    RFC2047:
    RFC2119:
    RFC3461:
    RFC4648:
    RFC5234:
    RFC5321:
    RFC5322:
    RFC6376:
    RFC6409:
    RFC6530:
    RFC8259:
    RFC8601:
    DKIMKEYS: I-D.chuang-dkim2-dns

informative:
    RFC5598:
    RFC8017:
    RFC8032:
    RFC8617:
    CONCLUDEARC: I-D.adams-arc-experiment-conclusion

--- abstract

DomainKeys Identified Mail v2 (DKIM2) permits a person, role, or
organization that owns a signing domain to document that it has
handled an email message by associating their domain with the
message.  This is achieved by providing a hash value that has
been calculated on the current contents of the message and then applying a cryptographic
signature that covers the hash values and other details about the
transmission of the message. Verification is performed by querying an entry
within the signing domain's DNS space to retrieve an appropriate public
key. As a message is transferred from author to recipient systems that
alter the body or header fields will provide details of their changes
and calculate new hash values. Further signatures 
will be added to provide a validatable "chain". This permits validators
to identify the nature of changes made by intermediaries and apply a
reputation to the systems that made changed. DKIM2 also allows
recipients to detect when messages have been unexpectedly "replayed"
and will ensure that Delivery Status Notifications are only sent
to entities that were involved in the transmission of a message.

--- middle

# Introduction

DomainKeys Identified Mail v2 (DKIM2) permits a person, role, or
organization to document that they have handled an email message by
associating a domain name [RFC1034] with the message [RFC5322]. A
public key signature is used to record that they have been able
to read the contents of the message and write to it.

Verification of claims is achieved by fetching a public key stored
in the DNS under the relevant domain and then checking the signature.

Message transit from author to recipient is through
Forwarders that typically make no substantive change to the message
content and thus preserve the DKIM2 signature. Where they do make
a change the changes they have made are documented so that
these can be "undone" and the original signature validated.

When a message is forwarded from one system to another an
additional DKIM2 signature is added on each occasion. This chain
of custody assists validators in distinguishing between messages that
were intended to be sent to a particular email address and those
that are being "replayed" to that address.

The chain of custody can also be used to ensure that delivery status
notifications are only sent to entities that were involved in the
transmission of a message.

Organizations that process a message can add to their signature
a request for feedback as to any opinion (for example, that the
email was considered to be spam) that the eventual recipient of
the message wishes to share.

## DKIM2 Architecture Documents

Readers are advised to be familiar with the material in TBA, TBA and TBA
which provide the background for the development of DKIM2, an overview
of the service, and deployment and operations guidance and advice.

# Terminology and Definitions

This section defines terms used in the rest of the document.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
[RFC2119].  These words take their normative meanings only when they
are presented in ALL UPPERCASE.

DKIM2 is designed to operate within the Internet Mail service, as
defined in [RFC5598].  Basic email terminology is taken from that
specification.

DKIM2 inherits many ideas from DKIM ([RFC6376]) which, for clarity
we refer to in this specification as DKIM1. In addition, some features
were influenced by experience with (see [CONCLUDEARC]) the experimental
ARC protocol ([RFC8617]).

Syntax descriptions use Augmented BNF (ABNF) [RFC5234].

This document uses JSON [RFC8259] to encode the "recipes" which
record changes made to a message header fields or body.
The JSON objects are then base64 encoded. This means that a
standard JSON parser can be used to create what may be quite
complex data structures. Unrecognised fields within JSON objects
MUST be ignored.

## Signer

Elements in the mail system that sign messages on behalf of a domain
are referred to as Signers.  These may be MUAs (Mail User Agents),
MSAs (Mail Submission Agents), MTAs (Mail Transfer Agents), or other
agents such as mailing list "exploders".  In general, any Signer will
be involved in the injection of a message into the message system in
some way.  The key point is that a message must be signed before it
leaves the administrative domain of the Signer.

## Forwarder

[RFC5598] defines a Relay as transmitting or retransmitting a message
but states that it will not modify the envelope information or the
message content semantics. It also defines a Gateway as a hybrid of
User and Relay that connects heterogeneous mail services. In this
document we use the concept of a Forwarder which is an MTA that receives
a message and then, as an alternative to delivering it into a
destination mailbox, can forward it on to another system in an
automated, pre-determined, manner.

## Reviser

As will be seen, a Forwarder may alter the message content or header
fields, in such a way that existing signatures on the message will
no longer validate. If so, then a record will be made of these
changes. We call a Forwarder that makes such changes a Reviser.

## Verifier

Elements in the mail system that verify signatures are referred to as
Verifiers.  These may be Forwarders, Revisers, MTAs, Mail Delivery
Agents (MDAs), or MUAs.
It is an expectation of DKIM2 that a recipient of a message will
wish to verify some or all signatures before determining whether or
not to accept the message or pass it on to another entity.

## Signing Domain

A domain name associated with a signature. This domain may be
associated with the author of an email, their organization, a
company hired to deliver the email, a mailing list operator, or
some other entity that handles email. What they have in common is
that at some point they had access to the entire contents of the
email and were in a position to add their signature to the email.

## Originator

The entity that creates and sends the initial form of a message.
The Originator adds the first Message-Instance header field (m=1) and
the first DKIM2-Signature header field (i=1) to the message.

## Header Field

As defined in [RFC5322], a header field is a single logical line in
the message header consisting of a field name, a colon, and a field
body (value).  In this document "header field" always refers to a
single field; "header fields" (plural) refers to multiple fields.
The unqualified term "header" is avoided to prevent ambiguity.

## Tag

A named element within a header field (see {{hfMessageInstance}}
and {{hfDKIM2signature}}).  A tag
consists of a tag-name and a tag-value separated by an equals sign.
Tags are separated by semicolons within the header field.

## Message Body

The content of an email message that follows the blank line after
the header fields, treated as a sequence of octets.  In this document,
the terms "body" and "message body" are used interchangeably.

## Hash

A fixed-length value produced by applying a cryptographic hash
function (such as SHA-256) to an input.  DKIM2 uses hashes to
create a compact, verifiable representation of message header fields
and the message body.

## Glossary

The following terms are used throughout this document:

DKIM1
: The original DomainKeys Identified Mail protocol as specified in
[RFC6376].

DKIM2-Signature
: A header field containing a cryptographic signature over the
Message-Instance and DKIM2-Signature header fields of a message,
along with metadata about the signing domain, SMTP envelope, and
timestamp.

Message-Instance
: A header field containing cryptographic hashes of the message
header fields and body, along with optional recipes that allow
undoing changes made at that hop.

Recipe
: A set of instructions encoded as a JSON object within the r= tag
of a Message-Instance header field.  Recipes allow a Verifier to
reconstruct the previous state of a message from its current state,
by specifying which parts of the header fields or body to copy and
which literal values to substitute.

Chain of Custody
: The sequence of DKIM2-Signature header fields on a message, each
recording the SMTP envelope addresses (MAIL FROM and RCPT TO) used
at each hop.  A valid chain of custody demonstrates that the message
followed a plausible path from Originator to the current recipient.

Selector
: A subdivision of the key namespace for a signing domain, used
to look up the public key in DNS.  The selector value is combined
with the signing domain to form the DNS query name:
selector._domainkey.domain.

## Whitespace

There are two forms of whitespace used in this specification:

*  WSP represents simple whitespace, i.e., a space or a tab character
   (formal definition in [RFC5234]).

*  FWS is folding whitespace.  It allows multiple lines separated by
   CRLF followed by at least one whitespace, to be joined.

The formal ABNF for these are (WSP given for information only):

    WSP =   SP / HTAB
    FWS =   [*WSP CRLF] 1*WSP

The definition of FWS is identical to that in [RFC5322] except for
the exclusion of obs-FWS.

## Imported ABNF Tokens

The following tokens are imported from other RFCs as noted.  Those
RFCs should be considered definitive.

The following tokens are imported from [RFC5321]:

*  "Domain"

*  "Forward-path"

*  "reverse-path"

The following tokens are imported from [RFC5322]:

*  "field-name" (name of a header field)

Other tokens not defined herein are imported from [RFC5234].  These
are intuitive primitives such as SP, HTAB, WSP, ALPHA, DIGIT, CRLF,
etc.

## Common ABNF Tokens

The following ABNF tokens are used elsewhere in this document:

    ALPHADIGITD  = (ALPHA / DIGIT / "-" / "_")

    textstring   =  [FWS] ALPHADIGITD *(ALPHADIGITD) [FWS]

    ALPHADIGITPS =  (FWS / ALPHA / DIGIT / "+" / "/")

    base64string =  ALPHADIGITPS *(ALPHADIGITPS) [[FWS] "=" [[FWS] "="]]

Note that base64strings are defined in [RFC4648], but that document
does not contain any ABNF. Note that a base64string MUST be padded
with trailing = characters if needed.

Note that the definition of base64string allows
for the presence of FWS, which simplifies folding header fields
to an allowable line length. FWS within base64strings will be
ignored when their value is being used.

# Signing and Verification Cryptographic Algorithms {#algorithms}

DKIM2 supports multiple hashing and digital signature algorithms. One
hash function (SHA256) is specified here and two signing algorithms
are defined by this specification: RSA-SHA256 and Ed25519-SHA256.
Signers and Verifiers MUST implement SHA256. Signers SHOULD implement
both RSA-SHA256 and Ed25519-SHA256. Verifiers MUST implement both
RSA-SHA256 and Ed25519-SHA256.

## The SHA256 Hashing Algorithm

The SHA256 hashing algorithm is used to compute body and
header hashes as defined in {{computing-body-hash}} and
{{computing-header-hash}}.

The resultant values are identified by the text string "sha256" and
placed into Message-Instance header fields.

## The RSA-SHA256 Signing Algorithm

The RSA-SHA256 Signing Algorithm computes a hash over all the Message-Instance
and DKIM2-Signature header fields as described in {{calculate-signature}} using
SHA-256 (FIPS-180-4-2015) as the hash-alg.  That
hash is then signed by the Signer using the RSA algorithm (defined in
PKCS#1 version 1.5 [RFC8017]) as the crypt-alg and the Signer's
private key.  The hash MUST NOT be truncated or converted into any
form other than the native binary form before being signed.  The
signing algorithm MUST use a public exponent of 65537.

Signers MUST use RSA keys of at least 1024 bits.  Verifiers MUST be able
to validate signatures with keys ranging from 1024 bits to 2048 bits, and
they MAY be able to validate signatures with larger keys.

The signature value (expressed in base64) is placed (with the identifying
text string "rsa-sha256") into DKIM2-Signature header fields.

## The Ed25519-SHA256 Signing Algorithm

The Ed25519-SHA256 Signing Algorithm computes a hash over all the Message-Instance
and DKIM2-Signature fields as described in {{calculate-signature}} using
SHA-256 (FIPS-180-4-2015) as the hash-alg. It signs the hash with the PureEdDSA
variant Ed25519, as defined in Section 5.1 of [RFC8032].

The signature value (expressed in base64) is placed (with the identifying
text string "ed25519-sha256") into DKIM2-Signature header fields.

## Other Algorithms

Other algorithms MAY be defined in the future.  Verifiers MUST ignore
any hashes or signatures using algorithms that they do not implement.

## Selectors

To support multiple concurrent public keys per signing domain, the
key namespace is subdivided using "selectors".

The number of public keys and corresponding selectors for each domain
is determined by the domain owner. Many domain owners will use just one
selector, whereas administratively distributed organizations can choose
to manage disparate selectors
and key pairs in different regions or on different email servers.
Selectors can also be used to delegate a signing authority, which
can be withdrawn at any time. Selectors also make it possible to
seamlessly replace keys on a routine basis by signing with a new
selector, while keeping the key associated with the old selector
available.

Periods are allowed in selectors and are component separators. Periods in
selectors define DNS label boundaries in a manner similar to the
conventional use in domain names.  This will allow portions of
the selector namespace to be delegated.

ABNF:

    selector = Domain

## Key Management {#key_management}

Some level of assurance is required that
a public key is associated with the claimed Signer. DKIM2
does this by fetching the key from the DNS for the domain specified
in the d= field of the DKIM2-Signature header field.

DKIM2 keys are stored in a subdomain named "_domainkey".  Given a
DKIM2-Signature field with a "d=" tag of "example.com" and a selector
of "foo.bar", the DNS query will be for "foo.bar._domainkey.example.com".

NOTE: these keys are no different, and are stored in the same locations
as those for DKIM1 ([RFC6376]).

Further details can be found in [DKIMKEYS].

# Recipes {#JSONrecipe}

A set of "recipes" is used to recreate the previous version of the body
and/or header fields of a message. The recipes are provided
within a JSON object with the schema:

    {
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "$id": "https://dkim2.org/schemas/recipe-v1",
      "title": "DKIM2 recipes",
      "description": "see draft-dkim-dkim2-spec",
      "type": "object",
      "properties": {
        "h": {
          "description": [ "recipes to recreate header fields",
            "keys are header field names matched case-insensitively",
            "and there MUST NOT be keys that differ only in case"],
          "oneOf": [
            {
              "description": "per-field-name recipe arrays",
              "type": "object",
              "minProperties": 1,
              "additionalProperties": { "$ref": "#/$defs/recipe-steps" }
            },
            {
              "description": "previous header state cannot be recreated",
              "type": "null"
            }
          ]
        },
        "b": {
          "description": "recipes to recreate the body",
          "oneOf": [
            {
              "description": "body recipes",
              "$ref": "#/$defs/recipe-steps"
            },
            {
              "description": "previous body state cannot be recreated",
              "type": "null"
            },
            {
              "description": "body was truncated (DSN)",
              "type": "object",
              "properties": {
                "z": { "type": "boolean", "const": true }
              },
              "required": ["z"], "additionalProperties": false
            }
          ]
        }
      },
      "anyOf": [
        { "required": ["h"] },
        { "required": ["b"] }
      ],
      "$defs": {
        "recipe-steps": {
          "type": "array",
          "items": {
            "oneOf": [
              {
                "description": "copy lines/fields, start to end inclusive",
                "type": "object",
                "properties": {
                  "c": { "type": "array",
                    "items": { "type": "integer", "minimum": 1 },
                    "minItems": 2, "maxItems": 2
                  }
                },
                "required": ["c"], "additionalProperties": false
              },
              {
                "description": "data lines/values to emit",
                "type": "object",
                "properties": {
                  "d": { "type": "array",
                    "items": { "type": "string" },
                    "minItems": 1
                  }
                },
                "required": ["d"], "additionalProperties": false
              }
            ]
          }
        }
      }
    }

Note that the specification of JSON schemas is maintained by the JSON Schema
organisation, and the relevant specification document is linked to by the
$schema field in each JSON schema.

## Header Recipes {#header-recipes}

A Header Recipe is an array of instructions applied to the specified
header fields with the given header field name. These instructions
are applied in order to the message which has been received
so as to recreate the message as it was before modifications were made.

If there is no "h" field in the JSON object then there was no
modification to the header fields.

If the "h" field value is null (there are no recipes for
any header field) then the previous state of the header fields
cannot be recreated. Verifiers of the message may be able to
determine, by seeing which entity makes this declaration, that
this is acceptable to them because, for example, that entity
is providing a contractually arranged service.

Matching of header field names is always done without regard to case.

If a header field name is not present in the JSON object then all
header fields with that header field name are to be retained.

If the recipe array for a header field name that is present in the
JSON object is empty then all instances of that header field are to
be removed to reinstate the previous state of the message.

Header fields are numbered "bottom up" (the opposite direction to
the body lines). That is to say, when walking the header fields
from the top of the message to end of the header fields then
the last header field instance
encountered with any particular header field name is numbered 1,
the header field (with the same header field name) above that is
numbered 2, and so on.

The header fields should be treated as
being unwrapped (in the normal [RFC5321] manner). That is, all
of the physical lines that form a single header field are
processed under the same logical number.

The recipes are processed in order and the resulting header
fields are emitted so that later header field will appear above
earlier header fields in the recreated message.

Each recipe step is a JSON object with exactly one key:

A "c" step has the form {"c": \[start, end\]}. The relevant header field
instances numbered from start to end inclusive, are to be emitted.
The start value of each "c" step MUST be in ascending order and
MUST be greater than the end value of all preceding "c" steps
for this header field name.

A "d" step has the form {"d": \["value1", "value2", ...\]}. Each
string in the array is treated as a value to which the
relevant header field name and a colon is prepended and a CRLF
is appended and the resultant string is then emitted. Note that
the way in which hashes are calculated (see {{computing-header-hash}})
means that no heed needs to be taken of wrapping
or the case of the header field name. The text strings MUST NOT
contain CR or LF characters. If a string is empty then the
CRLF will immediately follow the header field name and colon.

## Body Recipes {#body-recipes}

A Body Recipe is an array of instructions applied to the message
body which can recreate the message as it was before modifications
were made.

If there is no "b" field in the JSON object then there was no
modification to the message body. Note that the JSON schema
requires either "h" or "b" to be present.

If the "b" field is null (there are no recipes) then the previous
state of the message body
cannot be recreated. Verifiers of the message may be able to
determine, by seeing which entity makes this declaration, that
this is acceptable to them because, for example, that entity
is providing a contractually arranged service.

Body lines are numbered "top down" (the opposite direction to
the header fields). The first line of the body (immediately after
the blank line that indicates that there are no more header fields)
is numbered 1.

The recipes are processed in order and the resulting body lines
fields are emitted so that later lines will appear below
earlier lines in the recreated message.

Each recipe step is a JSON object with exactly one key:

A "c" step has the form {"c": \[start, end\]}. The message body lines
from start to end, inclusive, are to be emitted. The start value of
each "c" step MUST be in ascending order and MUST be greater than the
end value of all preceding "c" steps.

A "d" step has the form {"d": \["line1", "line2", ...\]}. Each
string in the array has a CRLF
appended and the resultant string is emitted. The text strings MUST NOT
contain CR or LF characters. If a string is empty then just
a CRLF is emitted.

A "z" step has the form {"z": true} and indicates that the
body was truncated (see the DSN handling in {{bounce}}).

# Message Hash Values {#messagehashes}

A set of cryptographic "hashes" are used to record the current
message body and header fields. The hashes are placed into the
h= tag of a Message-Instance header field.

To provide for algorithmic dexterity more that one hash value, using a
different algorithm MAY be supplied in the same Message-Instance
header field.

Since Message-Instance header fields are ignored when calculating the
header hash value, the body hash and header hash may be calculated in
any convenient order.

## Computing the Body Hash {#computing-body-hash}

The body of messages is treated as merely a string of octets. DKIM2
messages MAY be either in plain-text or in MIME format; no special
treatment is afforded to MIME content. Message attachments in MIME
format MUST be included in the content that is signed.

The DKIM2 body hash is calculated in the same manner as DKIM1's "simple"
scheme:

All empty lines at the end of the message body are ignored. An empty line
is a line of zero length after removal of the line terminator.  If there
is no body or no trailing CRLF on the message body, a CRLF is added. That
is "*CRLF" at the end of the body is converted to "CRLF".

No other changes are made to the body, which is then processed by the
relevant hash algorithm(s). The name of the hash and the hash value
(converted to base64 form) is then inserted into (Signers) or compared
to (Verifiers) the value of the "h=" tag of the Message-Instance header
field that is being created/verified. If multiple hashes are calculated
then multiple entries within the "h=" value will be inserted/compared.

## Computing the Header Fields Hash {#computing-header-hash}

The header fields hash calculation done by a Signer MUST apply the
following steps in the order given. A Verifier will need to do the
equivalent steps in order to check that the hash they have received
is correct.

*  Ignore some header fields

   When calculating the header field hash "Received" or "Return-Path"
   header fields MUST be ignored.
   These are Trace headers as described in [RFC5321]
   and serve only to document details of the SMTP transmission process.

   When calculating the header field hash any header field with
   a header field name starting with "X-" MUST be ignored.
   Currently deployed email systems use these fields as
   proprietary Trace headers which have no defined meaning for
   other systems and it considerably simplifies reporting
   on changes to header fields to ignore them.

   When calculating the header field hash any "Message-Instance" or
   "DKIM2-Signature" header fields MUST be ignored. These header
   fields will be included in the hash value that will be signed
   by a DKIM2-Signature header field and it simplifies implementations
   if they are not included twice, especially when determining
   whether all modifications to a message have been correctly declared.

   When calculating the header field hash any "DKIM-Signature" header
   fields and any header fields whose field name starts with "ARC-"
   MUST be ignored. Not including
   DKIM1 and ARC signatures means that systems that wish to add other
   types of signature as well as a DKIM2 signature are free to do this
   in any convenient order.

*  Convert all header field names (not the header field values) to
   lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".

*  Unfold all header field continuation lines as described in
   [RFC5322]; in particular, lines with terminators embedded in
   continued header field values (that is, CRLF sequences followed by
   WSP) MUST be interpreted without the CRLF.  Implementations MUST
   NOT remove the CRLF at the end of the header field value.

*  Convert all sequences of one or more WSP characters to a single SP
   character.  WSP characters here include those before and after a
   line folding boundary.

*  Delete all WSP characters at the end of each unfolded header field
   value.

*  Delete any WSP characters remaining before and after the colon
   separating the header field name from the header field value.  The
   colon separator MUST be retained.

*  Place the header fields in alphabetical order by the header field
   name.

*  If there is more than one header with the same header field name
   then the header fields are placed in the order in which they were
   likely to have been placed into the message header, that is from
   the last within the header upwards (the same ordering as is used
   in the header recipes (see {{header-recipes}}).

   It is sometimes suggested that some MTAs re-order
   header fields after they receive an email. If an MTA does change the
   order of header fields with the same header field name (and those
   header fields will be included in the hash calculation) then it is their
   responsibility to recover the original order
   before verifying an existing signature or passing a previously signed
   message to another MTA that may wish to do such verification.

*  The hash(es) of the concatenated header fields are calculated.

The name of the hash and the hash value
(converted to base64 form) is then inserted into (Signers) or compared
to (Verifiers) the value of the "h=" tag of the Message-Instance header
field that is being created/verified. If multiple hashes are calculated
then multiple entries within the "h=" value will be inserted/compared.

# The Message-Instance Header Field {#hfMessageInstance}

A Message-Instance header field documents the current contents of
the message and, in the case of a Reviser, records any relevant
changes that have been made to the incoming message.

The Message-Instance header field is a list of tag values as described
below. The m= and h= tags MUST be present. The r= tag is optional.

The tag identifiers (before the = sign) MUST be treated as case
insignificant, the tag value (after the = sign) is case significant. The
tags may appear in any order, but MUST be only one of each kind. Unknown
tags, for extensions, MUST be ignored.

ABNF:

    mi-field    = "Message-Instance:" mi-tag-list
    mi-tag-list = *([FWS] mi-tag [FWS] ";" [FWS])
    mi-tag      = mi-m-tag / mi-h-tag / mi-r-tag / x-tag
    x-tag       = ALPHA *(ALPHA / DIGIT / "_") "=" %x21-3A / %x3C-7E
                  ; for extension

## m= the revision number of the Message-Instance header field

The Originator of a message uses the
value 1. Further Message-Instance header fields are added with a value one
more than the current highest numbered Message-Instance header field. Gaps
in the numbering MUST be treated as making the whole message impossible
to verify.

ABNF:

    mi-m-tag    = %x6d [FWS] "=" [FWS] 1*DIGIT

## r= recipes to recreate the previous instance of the message

The r= tag value is the base64 encoded version of the JSON object that
contains the recipes that allow the previous instance of the message
to be recreated (see {{JSONrecipe}}}.

ABNF:

    mi-r-tag    = %x72 [FWS] "=" base64string

## h= the hash values for the message

The h= tag value contains the hash name, header hash value and body
hash value. Calculating the hash values is explained in {{messagehashes}}.

ABNF:

    mi-h-tag    = %x68 [FWS] "=" hash-set *("," hash-set )
    hash-set    = [FWS] hash-name [FWS] ":" header-hash ":" body-hash
    hash-name   = "sha256" / x-hash-name
    header-hash = base64string
    body-hash   = base64string
    x-hash-name = textstring ; for later expansion

# The DKIM2-Signature Header Field {#hfDKIM2signature}

The signature of the email is stored in a DKIM2-Signature header
field.  This header field contains tag values that provide the
signature and key-fetching data. The i=, m=, t=, mf=, rt=, d=
and s= tags MUST be present. The other tags are optional.

The tag identifiers (before the = sign) MUST be treated as case
insignificant, the tag value (after the = sign) is case significant. The
tags may appear in any order, but MUST be only one of each kind. Unknown
tags, for extensions, MUST be ignored.

ABNF:

    sig-field    = "DKIM2-Signature:" sig-tag-list
    sig-tag-list = *([FWS] sig-tag [FWS] ";" [FWS])
    sig-tag      = sig-i-tag / sig-m-tag / sig-t-tag / sig-mf-tag /
                   sig-rt-tag / sig-d-tag / sig-s-tag / sig-n-tag /
                   sig-f-tag / x-tag

It will be noted that we have not included a version number.  Experience
from IMF onwards shows that it is essentially impossible to change
version numbers. If it becomes necessary to change DKIM2 in the sort
of incompatible way that a v=2 / v=3 version number would support,
it is expected that header fields will be labelled as DKIM3 instead.

## i= the sequence number of the DKIM2-Signature header field

The Originator of a message uses the
value 1. Further DKIM2-Signature header fields are added with a value one
more than the current highest numbered DKIM2-Signature header field. Gaps
in the numbering MUST be treated as making the whole message unsigned.

ABNF:

    sig-i-tag = %x69 [FWS] "=" [FWS] 1*DIGIT

## m= the highest numbered Message-Instance header field

This value allows verifiers to determine which entity made a particular
revision to the message header fields or body.

ABNF:

    sig-m-tag = %x6d [FWS] "=" [FWS] 1*DIGIT

## n=  nonce value

This text value, if present, has a meaning to the creator of the signature
but MUST NOT be assumed to have any meaning to any other entity. It
MAY be used as an index into a database to assist in handling Delivery
Status Notifications or for any other purpose.

To discourage use of this tag field as an alternative to the use of more
appropriate header fields, the length of the string MUST NOT
exceed 64 characters and implementations SHOULD reject messages
where this limit has been ignored.

Note the value MUST be simple ASCII and MUST NOT contain semicolon.

ABNF:

    sig-n-tag   = %x6e [FWS] "=" [FWS] nonce-value
    nonce-value = *64(%x21-3A / %x3C-7E)
                      ; printable ASCII except semicolon, max 64 chars

## t=  signature timestamp

The time that this header field was created. The format is the number of
seconds since 00:00:00 on January 1, 1970 in the UTC time zone.  The value
is expressed as an unsigned integer in decimal ASCII.  This value
is not constrained to fit into a 31- or 32-bit integer.

Implementations SHOULD be prepared to handle values up to at least
10^12 (until approximately AD 200,000; this fits into 40 bits).
 
Implementations MAY ignore signatures that have a timestamp in the future.
Implementations MAY ignore signatures that are more than 14 days old.

ABNF:

    sig-t-tag    = %x74 [FWS] "=" [FWS] 1*DIGIT

## mf= the MAIL FROM used when the message was sent

DKIM2 records the [RFC5321] MAIL FROM value that was used when the message
was transmitted over an SMTP link from the signing MTA. Note that MAIL FROM
may be just "<>", for example for a Delivery Status Notification.

The value is recorded as the base64 encoding of the [RFC5321] reverse-path
because of the complex syntax of reverse-path values (which can include
characters which would confuse naive parsers of DKIM2-Signature header
fields). The angle brackets MUST be included, but any "Mail-parameters"
that were present after the reverse-path MUST NOT be included.

ABNF:

    sig-mf-tag  = %x6d %x66 [FWS] "=" base64string

## rt= the RCPT TO value(s) used when the message was sent

DKIM2 records the [RFC5321] RCPT TO value(s) that were used when the message
was transmitted over an SMTP link from the signing MTA.

The value is recorded as the base64 encoding of the [RFC5321] Forward-path
because of the complex syntax of Forward-path values (which can include
characters which would confuse naive parsers of DKIM2-Signature header
fields). The angle brackets MUST be included, but any "Rcpt-parameters"
that were present after the Forward-path MUST NOT be included.

When a message is intended for more than one recipient then the RCPT
TO values provided MAY include all of the recipients so that a single
copy of the email MAY be sent to all of the recipients in a single SMTP
transaction. Alternatively, multiple copies of the email may be
generated so as to not immediately reveal who else received the email.

However, if "bcc:" recipients are involved then in order to
meet the requirements of [RFC5322] Section 3.6.3 each and every
bcc recipients MUST NOT revealed to any other message recipient.

ABNF:

    sig-rt-tag = %x72 %x74 [FWS] "=" base64string *("," base64string)
                                        

## d=  the domain associated with this signature.

This domain is used to form the query for the public key. The domain MUST be a valid DNS
name under which the DKIM2 key record is published.

The domain name in the d= tag MUST exactly match the rightmost labels of
the domain name of the mf= tag. That is to say, the domain name of the
mf= tag MUST either match the d= domain exactly or be a sub-domain
of the d= domain name.

When the mf= domain is empty ("<>"), as will be the case for Delivery
Status Notifications (DSNs), then no match is required.

ABNF:

    sig-d-tag   = %x64 [FWS] "=" [FWS] Domain

## s= the signature value(s) for the message

The s= tag value contains the selector, signature algorithm name and
signature value. Calculating the value is explained in
{{calculate-signature}}.

The selector values subdivides the namespace for the domain being
used for signing.

The algorithm value is the one used to generate
the signature. Verifiers MUST support "RSA-SHA256" for which
the string "rsa-sha256" is used and "Ed25519-SHA256" for which the
string "ed25519-sha256" is used. See {{algorithms}} for a description
of these algorithms.

To provide for algorithmic dexterity more than one signature,
using different algorithms, MAY be supplied. Since the DNS lookup for
the public key will check that the k= algorithm value matches, a different
selector MUST necessarily be used for each signature.

ABNF:

    sig-s-tag   = %x73 [FWS] "=" [FWS] sig-set *( "," sig-set )
    sig-set     = selector [FWS] ":" [FWS] sig-name [FWS] ":" message-sig
    sig-name    = "rsa-sha256" / "ed25519-sha256" / x-sig-name
    x-sig-name  = textstring     ; for later extension
    message-sig = base64string

## f=  flags

Flags serve two purposes; they either report what has been done to
the message by the system creating the DKIM2-Signature or they make
a request to systems that handle the mail thereafter. Flags are
separated by commas, and optional white-space allows systems to
add several flags without creating long lines.

If a flag value is not recognised it MUST be ignored.

The flag values that report things are:

"exploded": this message (identified by its unique header hash value (recorded
in the h= JSON object of the relevant Message-Instance) is being sent to more
than one email address. An
MTA which receives a message MAY use this information to help it distinguish
between malicious "DKIM replay" and legitimate activity performed by
mailing list. If this flag is not present in at least one DKIM2-Signature
header field then an MTA MAY assume that only one copy of a particular
message (identified by relevant cryptographic hash values) is intended
to exist;

The flags values that make requests are:

"donotexplode": this Signer requests that the message not be sent to more
than one recipient. A system that, by local policy, ignores this request
MUST NOT allow any of the copies it creates to be forwarded on to any
MTA outside its control.

"donotmodify": this Signer requests that the message not be modified from
the form in which it is sent. A system that, by local policy, ignores this
request MUST NOT allow the message to be forwarded on to any
MTA outside its control.

"feedback": this Signer requests feedback about how this message is handled
during delivery and thereafter. This document does not describe what such
feedback might be or where it might be delivered. If this flag is absent
then feedback is explicitly not required.

ABNF:

    sig-f-tag        = %x66 [FWS] "=" [FWS] sig-f-tag-data
                       *( [FWS] "," [FWS] sig-f-tag-data)
    sig-f-tag-data   = "donotmodify" | "donotexplode" | "feedback" |
                       "exploded" | x-sig-f-tag-data
    x-sig-f-tag-data = textstring ; for later extension

# Signer Actions

This section gives the actions that need to be undertaken by the signer
of a message. They may be done in any appropriate order.

## Add any Necessary Message-Instance Header Fields

If a system is generating the initial form of a message or if
it is a Reviser that has made changes to the message body and/or
header fields then it MUST compute the body hash as described in
{{computing-body-hash}} and the hash of the header fields
as described in {{computing-header-hash}}.

If the message does not contain a Message-Instance header field then one
MUST be added.

If hashing the message body or relevant header fields does not
give the same hash values as those recorded in the highest version
(m=) Message-Instance header field then a new Message-Instance
header field MUST be added and if they are the same a new
Message-Instance header field SHOULD NOT be added.

A Message-Instance header field MUST contain "recipes" to be able to
recreate the message corresponding to the hash values in the
currently highest numbered Message-Instance header field, or a
null recipe to indicate that recreating the previous version
of the message will not be possible.

A system may add more than one Message-Instance header field if it
wishes to do so, but the DKIM2 design allows all modifications made by
any single system to be documented
in a single Message-Instance header field.

Note that the first (m=1) Message-Instance header field MAY
contain "recipes" if it is wished to record any changes made to a
message as it enters the DKIM2 ecosystem. All other Message-Instance
header fields SHOULD contain at least one "recipe".

## Provide a "Chain of Custody" for the Message {#chain-of-custody}

The DKIM2-Signature header field contains the MAIL FROM
and RCPT TO values that will be used when the message is transmitted,
so these [RFC5321] "envelope" values MUST be available to (or
deducible by) a Signer.

The receiver of a message will check for an exact match (including
the local parts of the email addresses) between the MAIL FROM / RCPT TO
[RFC5321] protocol values and the mf= and rt= values in the highest numbered
(most recent) DKIM2-Signature header field. It is acceptable for there to
be more RCPT TO email addresses recorded in rt= than are actually used in
the SMTP conversation, but any RCPT TO value which is used MUST be present.

Verifiers will check for a relaxed domain match (see {{relaxed-domain-match}})
between the signing domain (d=) and the domain in the MAIL FROM value.

When the message being signed already has a DKIM2-Signature header field
(i.e. it has already been transmitted at least once) then a valid
"chain of custody" MUST be apparent when all of the DKIM2-Signature header fields
are considered. This "chain of custody" contributes to the way in
which DKIM2 tackles "DKIM replay" attacks.

In any situation where a message will be forwarded in such a way that the
mf= on the outgoing message is such that the "chain of custody"
would be broken then the Signer MUST generate an extra DKIM2-Signature
header field that causes values to match, i.e. a record must be fabricated
that documents the mail being passed from one domain to another.

It will be noted that the
creation of this extra header field will require the Signer to have access
to a DKIM2 private key associated with a domain in the RCPT TO entry. This is
often achieved by the Signer creating the private key and never sharing it and
then taking one of two approaches to publishing the public key.
The first is to provide the public key (and selector value) to the domain owner
who creates an appropriate DNS entry. The alternative is for the Signer 
to create a public
key DNS entry within a part of the DNS that they control and the domain owner
publishes a CNAME pointing at this.

If an MTA does not change anything in the message which would require
a new Message-Instance header field and it is going to send it onwards
to a system that be able to verify the existing message (that is no
changes are made to the MAIL FROM and RCPT TO values) and there is no
other reason to add a DKIM2-Signature header field then the MTA MAY
choose not to add one. This means that an essentially transparent
SMTP forwarding system need not be made "DKIM2 aware". 

##  The Relaxed Domain Match Algorithm {#relaxed-domain-match}

To assist in addressing the "DKIM replay" problem DKIM2 provides a
"chain of custody" for every message. This is established by checking
that the MAIL FROM value recorded in every DKIM2-Signature header field
(except of course the i=1 instance) can be matched with a RCPT TO value
of the next lower numbered DKIM2-Signature header field.

It is also necessary to check DKIM2-Signature header fields for a match
between the signing domain (specified in the d= tag) and the MAIL FROM
domain.

To allow systems to use existing "bounce-handling" schemes with special
subdomains in their MAIL FROM values a "relaxed" approach is taken
to the matches between these values.

*  Only the domain part of the MAIL FROM and RCPT TO values is used
   for these matches The local part (and the @) are ignored.

*  If there is not an exact match between the domain names then labels
   are removed, one by one from the left hand side of the MAIL
   FROM domain name and the comparison is repeated.

*  If no labels remain then there is no match.

## Select a Private Key and Corresponding Selector Value {#signer_privatekey}

This specification does not define the basis by which a Signer should
choose which private key and selector value to use -- this will be a
matter of administrative convenience.  Distribution and management of private
keys is also outside the scope of this document.

## Calculate a Signature Value {#calculate-signature}

A Signer calculates a signature solely over the Message-Instance and
DKIM2-Signature header fields of the message. The hashes of
the body and other header fields are covered by the hashes in
the highest version (m=) Message-Instance header field and hence
the signature will in practice be signing the message as a whole.

Most cryptographic schemes proceed by first calculating a hash value
and then signing the hash value, but the DKIM2-Signature header field
only provides the final signature value. This means that there
is no difficulty if the hash value is inordinately long, or is
not emitted by the cryptographic routine being used.

The signature algorithm MUST apply the following steps
in the order given (which are not quite the same as the steps
undertaken in calculating header hashes).

*  Convert all relevant header field names (not the header field values) to
   lowercase.  For example, convert "DKIM2-signature" to "dkim2-signature".

*  Unfold all header field continuation lines as described in
   [RFC5322]; in particular, lines with terminators embedded in
   continued header field values (that is, CRLF sequences followed by
   WSP) MUST be interpreted without the CRLF.  Implementations MUST
   NOT remove the CRLF at the end of the header field value.

*  Delete all WSP characters. This means all WSP characters before and
   after the colon separating the header field name from the header
   field value, all WSP characters within the unfolded header field
   value and all trailing WPS characters before the CRLF. The colon
   separator and the CRLF MUST be retained.

*  Place the header fields in order. First come the Message-Instance
   header fields in ascending instance (m=) order. Second are the
   DKIM2-Signature header fields in ascending sequence (i=) order.
   Last of all is an incomplete DKIM2-Signature header field (the
   one that this system is creating) with all tags present except
   that the signature value(s) within the (s=) value are set to
   the null string (""). The incomplete header field MUST be
   unfolded, MUST have a trailing CRLF and MUST have spaces removed
   in just the same way as the
   complete header fields being processed.

*  The concatenated header fields are then fed to the signature
   algorithm(s). Once all the values are available the null 
   signature value strings
   are replaced by the base64 values of the signatures.

# Verification Requirements

The details of verification appear in {{verifier_actions}} below.
This section considers when verification should be performed and
how thorough it needs to be.

## Check Most Recent Signature and Hashes for the Message

A Verifier SHOULD check the validity of the most recently applied
(highest numbered i= value) DKIM2-Signature header field
and the associated (m=) Message-Instance before accepting an email.

If these checks
do not pass then a Delivery Status Notification (DSN) for the email MUST
NOT be generated thereafter -- hence the best strategy, if the email
is not wanted, is to reject it (with a 5xx error code) whilst the
relevant SMTP conversation is still ongoing. If the check gives
a TEMPFAIL result then a 4xx error code SHOULD be used to allow the
sending MTA to understand the situation.

If the checks do pass and it is later determined that the email
is unacceptable for any reason then a DSN MAY be created and
passed to the system that delivered the email. The details of
this procedure appear in {{bounce}}.

## Checking the Message-Instance Header Fields

If the message has been modified since its original creation then
the Message-Instance header fields will enable a Verifier to determine
whether or not all the changes made are correctly recorded
by using the "recipes" to construct each preceding version
of the message.

Note that if it is only the first form of the message is of
interest then all the "recipes" can be applied in turn and
only one hash value checked -- the correctness of the
intermediate hash values are not relevant to this assessment.

## Checking the DKIM2-Signature Header Fields

However, in order to check the chain of custody, to assess
whether the message has been exploded, to pick out
"feedback" requests to be honoured or to assign reputation to
Revisers then all of the DKIM2-Signature header fields
will have to checked for validity. The TBA document explores
these issues in more detail.

## Interpret Results/Apply Local Policy {#verifier_interpret}

It is beyond the scope of this specification to describe what actions
the recipient of an email performs, but mail carrying valid DKIM2
signatures gives the recipient opportunities that unauthenticated
email would not.  Specifically, an authenticated email provides
predictable information by which other decisions can reliably be
managed, such as trust and reputation.  Conversely, it is hard
to assign trust or reputation to unauthenticated email.

If an MTA wishes to reject messages where signatures are missing
or do not verify, the handling MTA
SHOULD use a 550/5.7.x reply code.

Where the Verifier is integrated within the MTA and it is not
possible to fetch the public key, perhaps because the key server is
not available, a temporary failure message MAY be generated using a
451/4.7.5 reply code.

Temporary failures such as inability to access the key server or
other external service are the only conditions that SHOULD use a 4xx
SMTP reply code.  In particular, cryptographic signature verification
failures MUST NOT provoke 4xx SMTP replies.

# Verifier Actions {#verifier_actions}

This section discusses the detail of the actions taken by a
Verifier. In essence
this will involve repeating all the actions taken by a Signer to
produce a Message-Instance or DKIM2-Signature header field. To
avoid a lot of repetition these actions will not be spelled out
in detail. Once a hash value has been calculated it is then
compared with the value reported by the Signer, or the Signer's
public key is used to determine whether a signature that has
been provided is correct.

When a Verifier is determining whether a particular DKIM2-Signature
header field it MUST consider the state of the message when that
header field was added to the message. That means it MUST first apply
all relevant recipes to reconstruct the body and header fields and it
MUST ignore any Message-Instance and DKIM2-Signature fields that
were added after that point.

## Output States

For compatibility with the Authentication-Results header field defined
in [RFC8601] a verification will result in one of four states: 

PASS:  The message was successfully verified.

FAIL:  The message could be verified but a hash or signature was not
       correct.

PERMERROR:  The message could not be verified due to some error that
      is unrecoverable, such as a required header field being absent
      or malformed.

TEMPERROR:  The message could not be verified due a temporary
      inability to retrieve a public key. A later attempt may
      produce a different.

A Verifier MAY cease verifying once a single failure is detected.

Verifiers wishing to communicate the results of verification to other
parts of the mail system may do so in whatever manner they see fit. If
they wish to provide a human-readable string to describe a failure
to verify (any state except PASS) then in order to provide the
maximum possible assistance to senders they SHOULD use the text
strings specified in this document. These human-readable messages
are described with m=`<x>` or tag=`<y>` placeholders, the `<x>` and `<y>` MUST
be replaced with the relevant ordinal or tag name (without the < and
> characters). Similarly `<value>` MUST be replaced by a relevant
string for the particular message.

If the verification is being performed during an SMTP protocol
conversation the human-readable string SHOULD be part of the
5xx or 4xx response string.

If the results of the verification are being communicated in a
Delivery Status Notification message ({{RFC3461}}) the
human-readable string should be included.

If, by local policy, a system wishes to accept a message which
has failed authentication it might choose to add an email header
field to the message before passing it on.  Any such header field
SHOULD include the human-readable string and 
SHOULD be inserted before any existing DKIM2-Signature or pre-existing
authentication status header fields in the header field block.  The
Authentication-Results: header field ([RFC8601]) MAY be used for this
purpose. It should be noted that any "Authentication-Results" header
field will count as a modification to the email if any further
DKIM2-Signature header fields are to be generated.

## Ensure that the DKIM2 Header Fields are Valid

Verifiers MUST meticulously validate the format and values of all
relevant Message-Instance and DKIM2-Signature header fields. It MUST
also ensure that all required instances of these header fields are
present and that all required tags are present. Recall however
that unknown tags MUST be ignored.

As a special case, there MUST not be a Message-Instance field
with a higher m= value than occurs in any DKIM2-Signature field.

Possible errors:

    PERMERROR Message-Instance m=<x> missing
    PERMERROR Message-Instance m=<x> syntax error
    PERMERROR Message-Instance m=<x> tag=<y> missing
    PERMERROR Message-Instance m=<x> is not signed
    PERMERROR DKIM2-Signature i=<x> missing
    PERMERROR DKIM2-Signature i=<x> syntax error
    PERMERROR DKIM2-Signature i=<x> tag=<y> missing

## Check the timestamps

Verifiers SHOULD return a failure it is more than 14 days since the
timestamp recorded in the "t=" tag of any DKIM2-Signature header field.

Possible errors:

    PERMERROR DKIM2-Signature i=<x> signature expired

## Check the Chain-of-Custody

As explained in {{chain-of-custody}} a Verifier MUST check an exact
match between the MAIL FROM and RCPT TO parameters used when delivering
a message and the values found in the mf= and rt= tags of the highest
numbered DKIM2-Signature header field. There may be extra values
in the rt= value, but all RCPT TO values actually used for
delivery MUST be present.

The values of domains MUST BE put into lower-case before doing these
checks. As is usual in email protocols the case of the local part of
an email address is assumed to matter. Note that these checks MUST NOT
use the relaxed domain match algorithm.

A Verifier SHOULD check that there is a relaxed domain match
(see {relaxed-domain-match}) between the signing domain of the
most recently applied DKIM2-Signature header field and the
mf= value in that header field.

Possible errors:

    PERMERROR: MAIL FROM <value> did not match
    PERMERROR: RCPT TO <value> did not match
    PERMERROR: MAIL FROM and d= do not match

## Fetch the Public Key

The public keys of all the signatures in DKIM2-Signature fields are
needed to complete the verification process. Details of key management and
representation are described in {{key_management}} and [DKIMKEYS].
The Verifier MUST validate the key record and MUST not use any public
key records that are malformed.

Note that DNS timeouts MUST be reported as TEMPERROR but a DNS
result that indicates the key is absent MUST be reported as a
PERMERROR. Additionally, as [DKIMKEYS] makes clear, if more than
one record is returned this is an error. The human-readable error
message SHOULD provide the selector value so that it is clear which
key has caused a problem.

Note that [DKIMKEYS] has retired the h= field and DKIM2 implementations
MUST ignore this tag if it is present.

Possible errors:

    TEMPERROR: DKIM2-Signature i=<x> public key <value> could not be fetched
    PERMERROR: DKIM2-Signature i=<x> public key <value> does not exist
    PERMERROR: DKIM2-Signature i=<x> public key <value> has multiple records
    PERMERROR: DKIM2-Signature i=<x> public key <value> has a syntax error
    PERMERROR: DKIM2-Signature i=<x> public key <value> algorithm mismatch
    PERMERROR: DKIM2-Signature i=<x> public key <value> has been revoked

## Perform the Signature Verification Calculation

Verifying a signature consists of actions semantically equivalent to the
following steps:

1.  Prepare a canonicalized version of the Message-Instance and DKIM2-Signature
    header fields as described in {{calculate-signature}}. The signature value(s)
    themselves will need to be removed to correspond with what was actually
    signed. Note that this canonicalized version does not actually replace
    the original content.

1.  Use the relevant public key value(s) to check the signature(s).

1.  If there is more than one signature provided then they MUST all be
    checked if the Verifier is able to do so. If any signature fails then
    an error SHOULD be reported. If all signatures that can be checked fail
    then PERMFAIL MUST be reported.

1.  If some signatures fail and other pass then any error that is
    reported should provide that information (e.g. PERMFAIL "rsa-sha256
    signature passed, ed25519-sha256 signature failed").

The reasoning for requiring that all signatures pass is that if a signature
scheme has recently become deprecated because it is known to be cryptographically
flawed then Signers will use a second (unbroken) signature scheme. However, such
a Signer may still provide the other signature for the benefit of Verifiers
that have yet to upgrade -- reasoning perhaps that attacks are too expensive
to be a very significant security issue. A Verifier that determines that
one signature passes whilst the other fails may well be in a position to
prevent an attack.

Possible errors:

    FAIL: DKIM2-Signature i=<x> public key <value> incorrect signature

## Validating Body and Header hashes

Verifying a hash value requires a Verifier to repeat the hash calculation
performed by the Signer as set out in {{computing-body-hash}}
and {{computing-body-hash}}. The values can then be directly compared.

Since there may be more than one hash algorithm given the human-readable
error message SHOULD indicate which algorithm's result failed to match.

Possible errors:

    FAIL: Message Instance m=<x> header hash <value> mismatch
    FAIL: Message Instance m=<x> body hash <value> mismatch

# Delivery Status Notifications in the DKIM2 ecosystem {#bounce}

In the DKIM2 ecosystem, when a message cannot be delivered then
this is reported to the sending machine by means of an {{RFC5321}}
return code or, if the SMTP session has completed, by generating
a Delivery Status Notification (DSN, as defined in {{RFC3461}}.

A DSN MUST be addressed to the MTA that sent the message. This
prevents "backscatter" by passing failures back along the chain
of MTAs that were in involved in passing the message forwards. This
is achieved by using the mf= tag from the highest numbered
DKIM2-Signature field. If this field is null ("mf=<>") then a DSN
MUST NOT be sent.

## DSN contents

As set out in {{RFC3461}}, the DSN has a top-level MIME part of
type `multipart/report`. Among other things, that MIME part must
contain a MIME part of type `message/rfc822` that holds either
the original message exactly as it was submitted by the sending system
or just the header fields of that message.

All relevant DKIM2-Signature header fields (and Message-Instance
header fields if the message body is supplied) MUST verify. The
DSN itself MUST have appropriate Message-Instance and DKIM2-Signature
fields, noting that the MAIL FROM to be used will be null ("<>").

If the message body has been truncated (rather than omitted
altogether) then in order to allow verification of the DNS
contents a Message-Instance header field MUST be added to the
message with a body recipe containing a {"z": true} step.

### Bounce Propagation

A Forwarder which receives a DSN MAY decide to propagate this
DSN to the MAIL FROM address used to deliver the message to it
(which can be found in the relevant DKIM2-Signature header field).
The DSN SHOULD be handled in the usual way, with Message-Instance
header fields documenting any changes and a DKIM2-Signature
field with an incremented hop count value added.

The Forwarder MAY alternatively decide to reconstruct the message
(or just the message header fields) as they were when the message
was delivered to the Forwarder and construct a DSN using that
information. The information in Message-Instance header fields
can be used to achieve this. The resultant DSN is sent to the
MAIL FROM address from the now highest numbered DKIM2-Signature
header field. Doing this will ensure that details of where the
message was forwarded to will not be revealed to the previous hop.

### Authentication of Inbound Bounce Notifications

When a system receives a DKIM2 signed bounce notification, and the
included original message is also DKIM2 signed, it SHOULD
verify that this message (or just the header fields if the body
is not present) has not been altered.

This means:

1. The DSN's DKIM2-Signature will have a signing domain that is
aligned with the recipient of the message that is being returned.
The recipient's address is located in the rt= tag of the
last (highest i= tag) DKIM2-Signature in the returned message.

1. The last (highest `i=` tag) DKIM2-Signature header field of the
returned message will be one that was generated by the system
receiving the bounce notification, determined by examining the
d= and mf= tags of that DKIM2-Signature header field.

1. The header fields of the embedded message (in the message/rfc822
MIME part) can be verified. If the message body is present then
that can also be verified by inspecting the Message-Instance
header field(s).

If the verification fails then the DSN MUST NOT be propagated
any further. If verification has been performed prior to
accepting the DSN from the sender the DSN SHOULD be rejected
with a 550/5.7.x return code. If the verification cannot be completed
because of a temporary issue (with DNS lookups) then a 4xx
return code should be used.

# Preventing Transport Conversions {#signer_normalize}

DKIM2's design is predicated on valid input.

In order to be signed a message will need to be in "network normal" format
(text is ASCII encoded, lines are separated with CRLF characters, etc.).

A message that is not compliant with [RFC5322], [RFC2045], [RFC2047]
and other relevant message format standards can be subject to attempts
by intermediaries to correct or interpret such content.  See Section 8
of [RFC6409] for examples of changes that are commonly made.  Such
"corrections" may invalidate DKIM2 signatures or have other undesirable
effects, including some that involve changes to the way a message is
presented to an end user.

When calculating the hash on messages that will be transmitted using
base64 or quoted-printable encoding, Signers MUST compute the hash
after the encoding.  Likewise, the Verifier MUST incorporate the
values into the hash before decoding the base64 or quoted-printable
text.  However, the hash MUST be computed before transport-level
encodings such as SMTP "dot-stuffing" (the modification of lines
beginning with a "." to avoid confusion with the SMTP end-of-message
marker, as specified in [RFC5321]).

Further, if the message contains local encoding that will be modified before transmission,
that modification to canonical [RFC5322] form MUST be done before signing.
In particular, bare CR or LF characters (used by some systems as a local line
separator convention) MUST be converted to the SMTP-standard CRLF
sequence before the message is signed.  Any conversion of this sort
SHOULD be applied to the message actually sent to the recipient(s),
not just to the version presented to the signing algorithm.

More generally, the Signer MUST sign the message as it is expected to
be received by the Verifier rather than in some local or internal form.

# EAI ([RFC6530]) Considerations for DKIM2

   TBA

# IANA Considerations

   TBA

# Security Considerations

   TBA

Changes from Earlier Versions
=============================

draft-ietf-dkim-dkim2-spec-01

Additions to terninology. Improved ABNF. Removed definition of tag-list
and placed relevant text in the two header field definitions. Untangled 
he description of what needs to be verified from the description of how
to verify and provided a list of human-readable strings to generate for
errors.

draft-ietf-dkim-dkim2-spec-00

Removed JSON for hashes, signatures and SMTP parameters. Provided
valid JSON for recipes and added "z" for truncated body.
Changed algorithm names for signing. Simplified the canonicalisation
performed for the header fields signed by DKIM2-Signature.
Changed v= to m= for message instance numbering.

General tidying up of specifying tag=value specifications and
associated ABNF. Various other fixes for issues flagged in WG.

\[\[This section to be removed by RFC Editor\]\]
