package DKIM2TestKeys;
use strict;
use warnings;

use Crypt::PK::RSA;
use Crypt::PK::Ed25519;
use MIME::Base64 qw(encode_base64);
use Mail::DKIM2::Common qw(parse_dkim_pubkey);

# Generate one shared RSA key and one shared Ed25519 key at load time.
# Reused across all domain/selector combos for speed.
my $RSA_KEY = Crypt::PK::RSA->new();
$RSA_KEY->generate_key(256, 65537);  # 256 bytes = 2048 bits

my $ED25519_KEY = Crypt::PK::Ed25519->new();
$ED25519_KEY->generate_key();

# Build DKIM TXT record strings
my $RSA_PUBKEY_TXT = "v=DKIM1; k=rsa; p="
    . encode_base64($RSA_KEY->export_key_der('public'), '');
my $ED25519_PUBKEY_TXT = "v=DKIM1; k=ed25519; p="
    . encode_base64($ED25519_KEY->export_key_raw('public'), '');

# Returns the private key object for a given selector.
# Ed25519 selectors start with "ed25519", everything else is RSA.
sub private_key {
    my ($domain, $selector) = @_;
    return $selector =~ /^ed25519/ ? $ED25519_KEY : $RSA_KEY;
}

# Returns PEM-encoded private key string for the given selector.
sub private_key_pem {
    my ($domain, $selector) = @_;
    my $key = private_key($domain, $selector);
    return $key->export_key_pem('private');
}

# Returns a pubkey callback sub for Verifier->set_pubkey_callback.
sub pubkey_callback {
    return sub {
        my ($signature, $idx) = @_;
        $idx //= 0;
        my $sel = $signature->selector($idx);
        my $alg = $signature->algorithm($idx) || '';
        my $txt = ($sel =~ /^ed25519/ || $alg eq 'ed25519')
            ? $ED25519_PUBKEY_TXT : $RSA_PUBKEY_TXT;
        return parse_dkim_pubkey($txt);
    };
}

1;
