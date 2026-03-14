Examples by Hannah Stern
========================

Files:
* pub.rsa/priv.rsa: RSA keypair used here
* pub.ed/priv.ed: ED25519 keypair used here
* signed1.eml: First simple signed email, according to my best
  understanding of draft-clayton-dkim2-spec-08

Note: The JSON in Message-Instance may not yet be in a final shape

Note: My interpretation of algorithm agility representation in
DKIM2-Signature's "s" tag is crude, just using multiples of 3
array elements (selector, algorithm, signature) instead of something
more structured.

Note: I think the algorithm specifiers would need to be changed to
include the hash name!
