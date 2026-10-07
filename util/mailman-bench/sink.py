"""Discard-all SMTP sink for the soak run.

Usage: sink.py PORT COUNTFILE
COUNTFILE is rewritten after every message with {"messages": N,
"recipients": N}.  Mailman batches recipients per SMTP transaction, so the
recipient count is the delivery count.
"""
import asyncio, json, os, sys
from aiosmtpd.controller import Controller

COUNTFILE = sys.argv[2]


class Sink:
    messages = 0
    recipients = 0

    async def handle_DATA(self, server, session, envelope):
        Sink.messages += 1
        Sink.recipients += len(envelope.rcpt_tos)
        tmp = COUNTFILE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump({'messages': Sink.messages,
                       'recipients': Sink.recipients}, f)
        os.replace(tmp, COUNTFILE)
        return '250 OK'


# The corpus has a 50 MB message; the aiosmtpd default limit is 32 MB.
ctl = Controller(Sink(), hostname='127.0.0.1', port=int(sys.argv[1]),
                 data_size_limit=512 * 1024 * 1024)
ctl.start()
asyncio.new_event_loop().run_forever()
