"""Make the signer gate usable from fixtures that sign over earlier hops.

Importing this module (a) points $DKIM2_DNS_JSON at the repo dns.json if it is
unset, and (b) makes dkim2sign.sign_message() ignore timestamps by default,
because those fixtures use fixed, old timestamps.  Tests of the gate itself
pass skip_timestamp_check explicitly.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import dkim2sign  # noqa: E402

os.environ.setdefault("DKIM2_DNS_JSON",
                      os.path.join(os.path.dirname(os.path.dirname(HERE)), "dns.json"))

if not getattr(dkim2sign.sign_message, "_old_ts_ok", False):
    _real = dkim2sign.sign_message

    def _sign_message_old_ts_ok(*args, **kw):
        kw.setdefault("skip_timestamp_check", True)
        return _real(*args, **kw)

    _sign_message_old_ts_ok._old_ts_ok = True
    dkim2sign.sign_message = _sign_message_old_ts_ok
