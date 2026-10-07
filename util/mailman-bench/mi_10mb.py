"""10 MB attachment through Message-Instance ingress -> pickle round trip
(as the queue does) -> decorate (DKIM2 wrap) -> egress, on one Mailman
checkout: median wall time per stage over 3 runs, then tracemalloc peak
above baseline for ingress and for decorate+egress, and the queue pickle
size.  m=2 must verify.

A nose2 test module, as it needs Mailman's test layer.  Copy it into the
checkout under test and run it in that checkout's venv, e.g. on the box:

  scp mi_10mb.py dkim2:/opt/mailman/src-test/src/mailman/handlers/tests/test_zz_mi_10mb.py
  ssh dkim2 'cd /opt/mailman/src-test && /opt/mailman/test-venv/bin/python \
      -m nose2 mailman.handlers.tests.test_zz_mi_10mb 2>&1 | grep BENCH'

Used for Task 16 (before: dkim2-3.3.10 at 4a9316a56).  Not a /opt/mailman/bench
build: it never touches the bench venvs.
"""
import base64
import email
import os
import pickle
import time
import tracemalloc
import unittest

from mailman.app.lifecycle import create_list
from mailman.config import config
from mailman.email.message import Message
from mailman.handlers import decorate
from mailman.handlers.message_instance import verify_message_instance
from mailman.interfaces.template import ITemplateManager
from mailman.testing.layers import ConfigLayer
from tempfile import TemporaryDirectory
from zope.component import getUtility


def _raw():
    data = base64.encodebytes(os.urandom(10 * 1024 * 1024))
    data = data.replace(b'\n', b'\r\n')
    return (b'To: ant@example.com\r\nFrom: aperson@example.com\r\n'
            b'Message-ID: <bench>\r\nSubject: bench\r\nMIME-Version: 1.0\r\n'
            b'Content-Type: multipart/mixed; boundary="xx"\r\n\r\n'
            b'--xx\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n'
            b'--xx\r\nContent-Type: application/octet-stream\r\n'
            b'Content-Transfer-Encoding: base64\r\n\r\n' + data +
            b'--xx--\r\n')


class TestBench(unittest.TestCase):
    layer = ConfigLayer

    def setUp(self):
        self._mlist = create_list('ant@example.com')
        self._mlist.preferred_language = 'en'
        td = TemporaryDirectory()
        self.addCleanup(td.cleanup)
        config.push('bench', """\
        [paths.testing]
        template_dir: {}
        [mta]
        message_instance: yes
        """.format(td.name))
        self.addCleanup(config.pop, 'bench')
        site_dir = os.path.join(config.TEMPLATE_DIR, 'site', 'en')
        os.makedirs(site_dir)
        for name, text in (('myheader.txt', 'List Header\n'),
                           ('myfooter.txt', '-- \nList Footer\n')):
            with open(os.path.join(site_dir, name), 'w') as fp:
                fp.write(text)
        m = getUtility(ITemplateManager)
        m.set('list:member:regular:header', None, 'mailman:///myheader.txt')
        m.set('list:member:regular:footer', None, 'mailman:///myfooter.txt')

    def _run(self, raw, trace):
        ingress = config.handlers['message-instance-ingress']
        egress = config.handlers['message-instance-egress']
        res = {}
        msg = email.message_from_bytes(raw, Message)
        msg.original_bytes = raw
        msgdata = {}
        if trace:
            tracemalloc.start()
            base = tracemalloc.get_traced_memory()[0]
        t = time.perf_counter()
        ingress.process(self._mlist, msg, msgdata)
        res['ingress_s'] = time.perf_counter() - t
        if trace:
            res['ingress_peak'] = tracemalloc.get_traced_memory()[1] - base
        pck = pickle.dumps(msg, pickle.HIGHEST_PROTOCOL)
        res['pickle'] = len(pck)
        del msg
        msg = pickle.loads(pck)
        del pck
        if trace:
            tracemalloc.reset_peak()
            base = tracemalloc.get_traced_memory()[0]
        t = time.perf_counter()
        decorate.process(self._mlist, msg, msgdata)
        res['decorate_s'] = time.perf_counter() - t
        t = time.perf_counter()
        egress.process(self._mlist, msg, msgdata)
        res['egress_s'] = time.perf_counter() - t
        if trace:
            res['out_peak'] = tracemalloc.get_traced_memory()[1] - base
            tracemalloc.stop()
        v, err = verify_message_instance(msg)
        self.assertEqual(v, 2, err)
        return res

    def test_bench(self):
        raw = _raw()
        times = [self._run(raw, False) for _ in range(3)]
        mem = self._run(raw, True)
        mib = 1024 * 1024
        out = ['raw {:.1f} MiB'.format(len(raw) / mib)]
        for k in ('ingress_s', 'decorate_s', 'egress_s'):
            out.append('{} median {:.3f}'.format(
                k, sorted(t[k] for t in times)[1]))
        out.append('ingress_peak {:.1f} MiB'.format(mem['ingress_peak'] / mib))
        out.append('out_peak {:.1f} MiB'.format(mem['out_peak'] / mib))
        out.append('pickle {:.1f} MiB'.format(mem['pickle'] / mib))
        print('\nBENCH: ' + '; '.join(out))
