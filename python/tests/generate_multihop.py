#!/usr/bin/env python3
"""Generate multi-hop test messages with recipes for the test suite.

All timestamps and content are fixed for reproducibility.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dkim2sign import (
    parse_message, sign_message, _header_name, build_message_instance,
    build_dkim2_signature, load_private_key, b64json,
)


KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        '..', 'keys')
EMAILS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'emails')
EXPECTED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'expected')


def key_path(name):
    return os.path.join(KEYS_DIR, name)


def reassemble(sig_headers, mi_headers, content_headers, body):
    """Reassemble a message from its parts."""
    output = b''
    for hdr in sig_headers:
        if isinstance(hdr, str):
            hdr = hdr.encode('utf-8')
        output += hdr + b'\r\n'
    for hdr in mi_headers:
        if isinstance(hdr, str):
            hdr = hdr.encode('utf-8')
        output += hdr + b'\r\n'
    for hdr in content_headers:
        if isinstance(hdr, str):
            hdr = hdr.encode('utf-8')
        output += hdr + b'\r\n'
    output += b'\r\n' + body
    return output


def split_headers(headers):
    """Split parsed headers into (sig_headers, mi_headers, content_headers)."""
    sigs, mis, content = [], [], []
    for hdr in headers:
        name = _header_name(hdr)
        if name == b'dkim2-signature':
            sigs.append(hdr)
        elif name == b'message-instance':
            mis.append(hdr)
        else:
            content.append(hdr)
    return sigs, mis, content


def generate_multihop_header_add():
    """Intermediary adds a List-Unsubscribe header. Recipe removes it."""
    raw = open(os.path.join(EMAILS_DIR, 'simple.eml'), 'rb').read()
    # Hop 1 sends to relay at test2 (chain of custody: rt must match next hop's mf domain)
    signed1 = sign_message(raw, 'ed25519', 'test1.dkim2.com',
                           key_path('ed25519._domainkey.test1.dkim2.com.pem'),
                           mailfrom='sender@test1.dkim2.com',
                           rcptto=['list@test2.dkim2.com'],
                           timestamp=1740000000)

    headers, body = parse_message(signed1)
    sig_hdrs, mi_hdrs, content_hdrs = split_headers(headers)

    # Add List-Unsubscribe and Received headers
    new_hdrs = [
        b'Received: from test1.dkim2.com by relay.example.com; Sat, 01 Mar 2026 12:01:00 +0000',
        b'List-Unsubscribe: <mailto:unsub@relay.example.com>',
    ] + content_hdrs

    # Recipe: remove List-Unsubscribe (empty array = remove all)
    recipes = {'h': {'list-unsubscribe': []}}

    mi2 = build_message_instance(new_hdrs, body, version=2)
    mi2 += '; r=' + b64json(recipes)

    mi_strs = [h.decode('utf-8') for h in mi_hdrs]
    sig_strs = [h.decode('utf-8') for h in sig_hdrs]

    private_key, algorithm = load_private_key(
        key_path('ed25519._domainkey.test2.dkim2.com.pem'))
    sig2 = build_dkim2_signature(
        mi_strs, sig_strs, mi2,
        'test2.dkim2.com', 'ed25519', private_key, algorithm,
        mailfrom='relay@test2.dkim2.com',
        rcptto=['recipient@example.com'],
        seq=2, mi_version=2, timestamp=1740001000,
    )

    return reassemble(
        [sig2.encode()] + sig_hdrs,
        [mi2.encode()] + mi_hdrs,
        new_hdrs, body,
    )


def generate_multihop_body_footer():
    """Intermediary appends a footer to body. Recipe keeps only original line."""
    raw = open(os.path.join(EMAILS_DIR, 'simple.eml'), 'rb').read()
    signed1 = sign_message(raw, 'ed25519', 'test1.dkim2.com',
                           key_path('ed25519._domainkey.test1.dkim2.com.pem'),
                           mailfrom='sender@test1.dkim2.com',
                           rcptto=['list@test2.dkim2.com'],
                           timestamp=1740000000)

    headers, body = parse_message(signed1)
    sig_hdrs, mi_hdrs, content_hdrs = split_headers(headers)

    # Append footer to body
    modified_body = body.replace(b'\r\n', b'\n').rstrip(b'\n')
    modified_body += b'\n\n-- \nSent via relay.example.com\n'
    modified_body = modified_body.replace(b'\n', b'\r\n')

    # Recipe: keep only line 1 of body
    recipes = {'b': [{'c': [1, 1]}]}

    mi2 = build_message_instance(content_hdrs, modified_body, version=2)
    mi2 += '; r=' + b64json(recipes)

    mi_strs = [h.decode('utf-8') for h in mi_hdrs]
    sig_strs = [h.decode('utf-8') for h in sig_hdrs]

    private_key, algorithm = load_private_key(
        key_path('ed25519._domainkey.test2.dkim2.com.pem'))
    sig2 = build_dkim2_signature(
        mi_strs, sig_strs, mi2,
        'test2.dkim2.com', 'ed25519', private_key, algorithm,
        mailfrom='relay@test2.dkim2.com',
        rcptto=['recipient@example.com'],
        seq=2, mi_version=2, timestamp=1740001000,
    )

    return reassemble(
        [sig2.encode()] + sig_hdrs,
        [mi2.encode()] + mi_hdrs,
        content_hdrs, modified_body,
    )


def generate_multihop_header_replace():
    """Intermediary replaces Subject header. Recipe restores original."""
    raw = open(os.path.join(EMAILS_DIR, 'simple.eml'), 'rb').read()
    signed1 = sign_message(raw, 'ed25519', 'test1.dkim2.com',
                           key_path('ed25519._domainkey.test1.dkim2.com.pem'),
                           mailfrom='sender@test1.dkim2.com',
                           rcptto=['list@test3.dkim2.com'],
                           timestamp=1740000000)

    headers, body = parse_message(signed1)
    sig_hdrs, mi_hdrs, content_hdrs = split_headers(headers)

    # Replace Subject header
    modified_hdrs = []
    for hdr in content_hdrs:
        if _header_name(hdr) == b'subject':
            modified_hdrs.append(b'Subject: [MODIFIED] Simple test message')
        else:
            modified_hdrs.append(hdr)

    # Recipe: restore original Subject (text = value without field name)
    recipes = {'h': {'subject': [{'d': [' Simple test message']}]}}

    mi2 = build_message_instance(modified_hdrs, body, version=2)
    mi2 += '; r=' + b64json(recipes)

    mi_strs = [h.decode('utf-8') for h in mi_hdrs]
    sig_strs = [h.decode('utf-8') for h in sig_hdrs]

    private_key, algorithm = load_private_key(
        key_path('ed25519._domainkey.test3.dkim2.com.pem'))
    sig2 = build_dkim2_signature(
        mi_strs, sig_strs, mi2,
        'test3.dkim2.com', 'ed25519', private_key, algorithm,
        mailfrom='relay@test3.dkim2.com',
        rcptto=['recipient@example.com'],
        seq=2, mi_version=2, timestamp=1740001000,
    )

    return reassemble(
        [sig2.encode()] + sig_hdrs,
        [mi2.encode()] + mi_hdrs,
        modified_hdrs, body,
    )


def generate_multihop_dup_headers():
    """Intermediary adds duplicate Authentication-Results headers.

    Tests that duplicate headers are sorted bottom-up in the header hash.
    The original message has one Authentication-Results, the relay adds two
    more on top. The recipe keeps only the original (instance 1, bottom-up).
    """
    raw = open(os.path.join(EMAILS_DIR, 'dupheaders.eml'), 'rb').read()
    signed1 = sign_message(raw, 'ed25519', 'test1.dkim2.com',
                           key_path('ed25519._domainkey.test1.dkim2.com.pem'),
                           mailfrom='sender@test1.dkim2.com',
                           rcptto=['relay@test2.dkim2.com'],
                           timestamp=1740000000)

    headers, body = parse_message(signed1)
    sig_hdrs, mi_hdrs, content_hdrs = split_headers(headers)

    # Relay adds two more Authentication-Results on top
    new_hdrs = [
        b'Authentication-Results: relay.test2.dkim2.com; spf=pass',
        b'Authentication-Results: relay.test2.dkim2.com; dkim=pass',
    ] + content_hdrs

    # Recipe: keep only the original 3 Authentication-Results (instances 1-3,
    # bottom-up = the 3 that were in the original message)
    recipes = {'h': {'authentication-results': [{'c': [1, 3]}]}}

    mi2 = build_message_instance(new_hdrs, body, version=2)
    mi2 += '; r=' + b64json(recipes)

    mi_strs = [h.decode('utf-8') for h in mi_hdrs]
    sig_strs = [h.decode('utf-8') for h in sig_hdrs]

    private_key, algorithm = load_private_key(
        key_path('ed25519._domainkey.test2.dkim2.com.pem'))
    sig2 = build_dkim2_signature(
        mi_strs, sig_strs, mi2,
        'test2.dkim2.com', 'ed25519', private_key, algorithm,
        mailfrom='relay@test2.dkim2.com',
        rcptto=['recipient@example.com'],
        seq=2, mi_version=2, timestamp=1740001000,
    )

    return reassemble(
        [sig2.encode()] + sig_hdrs,
        [mi2.encode()] + mi_hdrs,
        new_hdrs, body,
    )


def generate_multihop_3hop_dup_headers():
    """Three-hop chain where each hop adds Authentication-Results headers.

    Hop 1: Original message with 3 Authentication-Results
    Hop 2: Relay adds 2 more on top (total 5), recipe keeps original 3
    Hop 3: Final MX adds 1 more on top (total 6), recipe keeps hop 2's 5

    This tests that bottom-up ordering is consistent across multiple undo steps.
    """
    raw = open(os.path.join(EMAILS_DIR, 'dupheaders.eml'), 'rb').read()
    signed1 = sign_message(raw, 'ed25519', 'test1.dkim2.com',
                           key_path('ed25519._domainkey.test1.dkim2.com.pem'),
                           mailfrom='sender@test1.dkim2.com',
                           rcptto=['relay@test2.dkim2.com'],
                           timestamp=1740000000)

    # Hop 2: relay adds 2 Authentication-Results
    headers, body = parse_message(signed1)
    sig_hdrs1, mi_hdrs1, content_hdrs1 = split_headers(headers)

    hop2_hdrs = [
        b'Authentication-Results: relay.test2.dkim2.com; spf=pass',
        b'Authentication-Results: relay.test2.dkim2.com; dkim=pass',
    ] + content_hdrs1

    recipes2 = {'h': {'authentication-results': [{'c': [1, 3]}]}}
    mi2 = build_message_instance(hop2_hdrs, body, version=2)
    mi2 += '; r=' + b64json(recipes2)

    mi_strs1 = [h.decode('utf-8') for h in mi_hdrs1]
    sig_strs1 = [h.decode('utf-8') for h in sig_hdrs1]

    private_key2, algorithm2 = load_private_key(
        key_path('ed25519._domainkey.test2.dkim2.com.pem'))
    sig2 = build_dkim2_signature(
        mi_strs1, sig_strs1, mi2,
        'test2.dkim2.com', 'ed25519', private_key2, algorithm2,
        mailfrom='relay@test2.dkim2.com',
        rcptto=['mx@test3.dkim2.com'],
        seq=2, mi_version=2, timestamp=1740001000,
    )

    hop2_msg = reassemble(
        [sig2.encode()] + sig_hdrs1,
        [mi2.encode()] + mi_hdrs1,
        hop2_hdrs, body,
    )

    # Hop 3: final MX adds 1 more Authentication-Results
    headers3, body3 = parse_message(hop2_msg)
    sig_hdrs2, mi_hdrs2, content_hdrs2 = split_headers(headers3)

    hop3_hdrs = [
        b'Authentication-Results: mx.test3.dkim2.com; dmarc=pass',
    ] + content_hdrs2

    # Recipe: keep all 5 from hop 2 (instances 1-5 bottom-up)
    recipes3 = {'h': {'authentication-results': [{'c': [1, 5]}]}}
    mi3 = build_message_instance(hop3_hdrs, body3, version=3)
    mi3 += '; r=' + b64json(recipes3)

    mi_strs2 = [h.decode('utf-8') for h in mi_hdrs2]
    sig_strs2 = [h.decode('utf-8') for h in sig_hdrs2]

    private_key3, algorithm3 = load_private_key(
        key_path('ed25519._domainkey.test3.dkim2.com.pem'))
    sig3 = build_dkim2_signature(
        mi_strs2, sig_strs2, mi3,
        'test3.dkim2.com', 'ed25519', private_key3, algorithm3,
        mailfrom='mx@test3.dkim2.com',
        rcptto=['recipient@example.com'],
        seq=3, mi_version=3, timestamp=1740002000,
    )

    return reassemble(
        [sig3.encode()] + sig_hdrs2,
        [mi3.encode()] + mi_hdrs2,
        hop3_hdrs, body3,
    )


TESTS = {
    'multihop-header-add': generate_multihop_header_add,
    'multihop-body-footer': generate_multihop_body_footer,
    'multihop-header-replace': generate_multihop_header_replace,
    'multihop-dup-headers': generate_multihop_dup_headers,
    'multihop-3hop-dup-headers': generate_multihop_3hop_dup_headers,
}


def main():
    os.makedirs(EXPECTED_DIR, exist_ok=True)
    for name, generator in TESTS.items():
        data = generator()
        outpath = os.path.join(EXPECTED_DIR, f'{name}.eml')
        with open(outpath, 'wb') as f:
            f.write(data)
        print(f'  GENERATED: {name}')


if __name__ == '__main__':
    main()
