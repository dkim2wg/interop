# DKIM2 Demonstration Server

Deploy a working DKIM2 mail server on a small Ubuntu VPS for interoperability
testing. The server runs Postfix with `dkim2-milter.pl` for DKIM2 signing
and verification.

## Prerequisites

- Ubuntu 22.04+ VPS (1 vCPU, 1GB RAM, 20GB disk is sufficient)
- Root SSH access
- Domain `dkim2.com` with DNS control

## Pre-deployment DNS

Before running the setup script, publish these DNS records:

```
; A record
mail.dkim2.com.    IN  A  <VPS-IP>

; PTR (reverse DNS) — configure via your VPS provider
<VPS-IP>  →  mail.dkim2.com

; MX records
dkim2.com.          IN  MX  10  mail.dkim2.com.
test1.dkim2.com.    IN  MX  10  mail.dkim2.com.
test2.dkim2.com.    IN  MX  10  mail.dkim2.com.
test3.dkim2.com.    IN  MX  10  mail.dkim2.com.
test4.dkim2.com.    IN  MX  10  mail.dkim2.com.
test5.dkim2.com.    IN  MX  10  mail.dkim2.com.
```

## Deployment

```bash
ssh root@dkim2.com 'bash -s' < deploy/setup-dkim2-demo.sh
```

The script will:

1. Install system packages (Postfix, certbot, cpanminus, etc.)
2. Install Perl dependencies from CPAN
3. Create a `dkim2` system user
4. Clone this repository to `/opt/dkim2/interop`
5. Generate RSA-2048 and Ed25519 production keys for `dkim2.com`
6. Copy interop test keys for `test1-5.dkim2.com`
7. Obtain a Let's Encrypt TLS certificate for `mail.dkim2.com`
8. Configure Postfix with milter integration
9. Install and start the `dkim2-milter` systemd service
10. Print DNS records for DKIM selectors that you need to publish

## Post-deployment DNS

After running the setup script, it prints DKIM selector TXT records.
Publish those, plus SPF and DMARC records. You can regenerate them
any time:

```bash
ssh root@dkim2.com bash /opt/dkim2/interop/deploy/generate-dns-records.sh
```

## Architecture

```
Internet → Postfix (port 25) → dkim2-milter.pl → deliver/relay
                                  ↓
                          /etc/dkim2/keys/     (signing keys)
                          /var/spool/dkim2/    (MI snapshots)
```

A single milter instance handles both:
- **Inbound**: verify DKIM2 signatures, add `Authentication-Results` header
- **Outbound**: sign with DKIM2, add `Message-Instance` header

## Directory layout on server

```
/opt/dkim2/interop/               Git clone of this repo
/etc/dkim2/keys/                  Keydir for milter
  dkim2.com/sel1.key              Production RSA-2048 key
  dkim2.com/ed25519.key           Production Ed25519 key
  test1.dkim2.com/sel1.key        Interop test keys
  test1.dkim2.com/ed25519.key
  ...
/var/spool/dkim2/snapshots/       MI message snapshots
```

## Service management

```bash
# Milter logs
journalctl -u dkim2-milter -f

# Restart milter (e.g. after git pull)
systemctl restart dkim2-milter

# Mail logs
tail -f /var/log/mail.log

# Postfix
systemctl restart postfix
```

## Updating

```bash
cd /opt/dkim2/interop && git pull
systemctl restart dkim2-milter
```

## Testing

From a remote machine:

```bash
# Basic SMTP connectivity
swaks --to test@dkim2.com --server mail.dkim2.com

# Check DNS
dig +short TXT sel1._domainkey.dkim2.com

# Check delivered headers for DKIM2-Signature and Authentication-Results
```

### Multi-hop test

The `looper` alias forwards through dkim2.com and then into Mailman,
producing `i=1` (dkim2.com) and `i=2` (Mailman) signatures with MI headers.

Install the helper script and set up the alias:

```bash
install -m 755 deploy/looper-forward /usr/local/bin/looper-forward

# Add to /etc/aliases:
#   looper: |"/usr/local/bin/looper-forward"
newaliases
```

The script strips `Delivered-To` (added by Postfix during alias delivery)
before re-injecting, so the re-injected message matches the inbound m=1
snapshot and no spurious m=2 MI header is generated.

### Cross-implementation testing

Other implementers send DKIM2-signed mail to `test@dkim2.com` and check
`Authentication-Results` headers in the response or server logs.
