package Mail::DKIM2::MessageInstance;
use strict;
use warnings;


use Crypt::Digest::SHA256;
use Crypt::Digest::SHA512 qw(sha512 sha512_b64);
use Email::MIME;
use MIME::Base64 qw(encode_base64 decode_base64);
use Algorithm::Diff;
use List::Util qw(max);
use Carp;

use Mail::DKIM2::Common qw(
    should_skip
    dkim2_canonicalize_header
    digest64
    encode_tag_json
    decode_tag_json
    extract_mi_version
);

our $DEBUG = 0;

# spec-05 §3.1: two hashing algorithms are defined. Verifiers MUST implement
# both; Signers MAY implement either or both (we default to sha256).
my %HASH_ALGS = (
    sha256 => \&Crypt::Digest::SHA256::sha256,
    sha512 => \&Crypt::Digest::SHA512::sha512,
);

sub hash_algs { return { %HASH_ALGS } }

# spec-05 §7.3: h= is hash-set *("," hash-set), hash-set = alg ":" hh ":" bh.
# Hash names are lowercased -- RFC 5234 makes ABNF quoted strings
# case-insensitive. All FWS is stripped (§2.12): it may appear anywhere
# inside a base64 value (e.g. a folded header), not just at either end.
sub parse_hash_sets {
    my ($h_tag) = @_;
    my @sets;
    for my $item (split /,/, $h_tag) {
        $item =~ s/[\s\r\n]//g;
        my @parts = split /:/, $item;
        next unless @parts == 3;
        push @sets, [lc $parts[0], $parts[1], $parts[2]];
    }
    return \@sets;
}

# FILTHY PATCHING (needed for undo to work with Email::Simple)
BEGIN {
    # function to replace headers from the bottom up
    if (!Email::Simple::Header->can('header_set_reverse')) {
        *Email::Simple::Header::header_set_reverse = sub {
            my $self = shift;
            my $h = shift;
            my @vals = @_;
            my $headers = $self->{headers};
            my $max = @$headers / 2 - 1;
            for my $idx (map { $_ * 2 } reverse 0..$max) {
                next unless lc($headers->[$idx]) eq lc($h);
                if (@vals) {
                    $headers->[$idx+1] = shift @vals;
                } else {
                    splice(@$headers, $idx, 2);
                }
            }
            unshift @$headers, ($h, $_) for @vals;
        };
    }

    # function to only keep headers that match an expression
    if (!Email::Simple::Header->can('header_filter')) {
        *Email::Simple::Header::header_filter = sub {
            my $self = shift;
            my $h = shift;
            my $keep = shift;
            my $headers = $self->{headers};
            my $max = @$headers / 2 - 1;
            for my $idx (map { $_ * 2 } reverse 0..$max) {
                next unless lc($headers->[$idx]) eq lc($h);
                next if $keep->($headers->[$idx+1]);
                splice(@$headers, $idx, 2);
            }
        };
    }
}

# --- Tag accessors ---

sub set_tag {
    my ($self, $k, $v) = @_;
    $self->{bits}{$k} = $v;
}

sub get_tag {
    my ($self, $k) = @_;
    return $self->{bits}{$k};
}

# The header-hash component (base64) of this Message-Instance's h= tag.
sub header_hash { return $_[0]->{bits}{h1} }

# Mark the body recipe as null per spec-04 §4.2: the body changed but the
# previous state cannot be recreated. as_string() then emits "b": null.
sub set_null_body_recipe {
    my ($self) = @_;
    $self->{bits}{rb} = \'null';   # scalar-ref sentinel
}

# True if this instance declares the previous state non-recreatable (a null
# "b" recipe). Such an instance cannot be undone to a prior version. Under
# draft-04 §5.1 a header recipe can no longer be null, so only the body
# recipe can render an instance unrecoverable.
sub unrecoverable {
    my ($self) = @_;
    return $self->{bits}{rb_null} ? 1 : 0;
}

# --- Wire format: m=N; h=sha256:header_hash:body_hash; r=<b64json> ---

sub as_string {
    my ($self) = @_;
    my %data = %{$self->{bits}};
    my $m = delete $data{m};
    my $h1 = delete $data{h1};
    my $b1 = delete $data{b1};
    my $hashes = delete $data{hashes};
    unless ($hashes && %$hashes) {
        # Back-compat: bits built directly with bare h1/b1 and no hashes map
        # (e.g. hand-constructed objects in tests) still emit a sha256 set.
        $hashes = (defined $h1 || defined $b1) ? { sha256 => [ $h1 // '', $b1 // '' ] } : {};
    }

    # spec-05 §7.3: h= is hash-set *("," hash-set) -- one hash-set per
    # configured algorithm, emitted in the signer's chosen order (default:
    # sha256 only; the signer default MUST NOT change).
    my @algs = @{ $self->{algs} || ['sha256'] };
    my @sets;
    for my $alg (@algs) {
        my $pair = $hashes->{$alg} or next;
        push @sets, "$alg:$pair->[0]:$pair->[1]";
    }
    my $result = "m=$m; h=" . join(',', @sets);

    # Build r= tag JSON if there are recipes
    my %recipe_json;
    if (exists $data{rb}) {
        if (ref $data{rb} eq 'SCALAR' && ${$data{rb}} eq 'null') {
            $recipe_json{b} = undef;          # encodes as JSON null
            delete $data{rb};
        } else {
            $recipe_json{b} = _encode_recipe_list(delete $data{rb});
        }
    }
    if (exists $data{rh}) {
        my $rh = delete $data{rh};
        my %encoded;
        # spec-05 §5.1: header field names in the JSON Recipes MUST be lower
        # case (matching against the message stays case-insensitive).
        for my $h (sort keys %$rh) {
            $encoded{lc $h} = _encode_recipe_list($rh->{$h});
        }
        $recipe_json{h} = \%encoded;
    }

    if (keys %recipe_json) {
        $result .= "; r=" . encode_tag_json(\%recipe_json);
    }
    $result .= ";";

    return $result;
}

# Convert internal recipe list to wire format
# Internal: [from,to] arrays for copy ranges, strings for literal content
# Wire: {"c": [from,to]} for copy, {"d": ["val1",...]} for data
sub _encode_recipe_list {
    my ($list) = @_;
    my @encoded;
    my @pending_strings;
    for my $item (@$list) {
        if (ref $item eq 'ARRAY') {
            # Flush any pending strings as a {"d": [...]} step
            if (@pending_strings) {
                push @encoded, { d => [@pending_strings] };
                @pending_strings = ();
            }
            push @encoded, { c => $item };
        } else {
            push @pending_strings, $item;
        }
    }
    if (@pending_strings) {
        push @encoded, { d => [@pending_strings] };
    }
    return \@encoded;
}

# --- Parsing ---

sub parse {
    my ($class, $header) = @_;
    my $self = bless {}, ref($class) || $class;

    # Strip leading whitespace
    $header =~ s/^\s+//;

    # Parse tag-value format: m=N; h=...; r=...
    my %tags;
    for my $part (split /\s*;\s*/, $header) {
        next unless $part =~ /^(\w+)\s*=\s*(.*)/s;
        my ($name, $val) = ($1, $2);
        $val =~ s/\s//gs;
        $tags{$name} = $val;
    }

    die "missing m= tag in Message-Instance header"
        unless exists $tags{m};
    $self->{bits}{m} = $tags{m};

    # spec-05 §7.3: h= is a list of hash-sets
    if (exists $tags{h}) {
        my $sets = parse_hash_sets($tags{h});

        # §7.3: an algorithm MUST NOT be present more than once. Check the
        # LIST returned by parse_hash_sets, not a hash keyed by algorithm --
        # a hash would let the second occurrence silently overwrite the
        # first, hiding the duplicate. Hash names are already lowercased by
        # parse_hash_sets (RFC 5234 makes ABNF quoted strings
        # case-insensitive), so this comparison is case-insensitive too.
        # This must run before any hash is computed or compared.
        my %seen;
        for my $s (@$sets) {
            if ($seen{$s->[0]}++) {
                die "PERMERROR Message-Instance m=$tags{m} has a duplicate hash algorithm\n";
            }
        }

        for my $s (@$sets) {
            $self->{bits}{hashes}{$s->[0]} = [$s->[1], $s->[2]];
        }
        # Back-compatible aliases for the sha256 hash-set
        if (my $sha256 = $self->{bits}{hashes}{sha256}) {
            @{$self->{bits}}{qw(h1 b1)} = @$sha256;
        }
    }

    if (exists $tags{r}) {
        # spec-05 §11.2: a bad base64 r= value and a post-decode JSON parse
        # failure are different errors and must stay distinct: base64
        # failure -> "syntax error" (§11.2 lists this explicitly for
        # malformed field content); JSON failure -> "contains invalid JSON".
        # decode_base64() is lenient (silently drops non-alphabet
        # characters rather than failing), so a strict format check is
        # needed here to actually catch malformed base64 -- otherwise it
        # would just decode to garbage bytes that happen to also fail JSON
        # parsing, mislabelling the error.
        if ($tags{r} !~ m{\A(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\z}) {
            die "PERMERROR Message-Instance m=$tags{m} syntax error\n";
        }
        my $recipe_data = eval { decode_tag_json($tags{r}) };
        if ($@) {
            die "PERMERROR Message-Instance m=$tags{m} contains invalid JSON\n";
        }
        # A present-but-null "b"/"h" (spec §4.1/§4.2) means the previous state
        # cannot be recreated — distinct from an absent field (no change).
        if (exists $recipe_data->{b}) {
            if (defined $recipe_data->{b} && ref($recipe_data->{b}) eq 'ARRAY') {
                $self->{bits}{rb} = _decode_recipe_list($recipe_data->{b});
            } else {
                $self->{bits}{rb_null} = 1;
            }
        }
        if (exists $recipe_data->{h}) {
            if (defined $recipe_data->{h} && ref($recipe_data->{h}) eq 'HASH' && keys %{$recipe_data->{h}}) {
                my %rh;
                for my $h (keys %{$recipe_data->{h}}) {
                    $rh{$h} = _decode_recipe_list($recipe_data->{h}{$h});
                }
                $self->{bits}{rh} = \%rh;
            } else {
                # draft-04 §5.1 removed the null header recipe: a present "h"
                # MUST be a non-empty object. Reject anything else.
                die "header recipe is null: not permitted under draft-04 \xA75.1\n";
            }
        }
    }

    return $self;
}

# Convert wire format recipe list to internal format
# Wire: {"c": [from,to]} for copy, {"d": ["val1",...]} for data
# Internal: [from,to] arrays for copy ranges, strings for literal content
sub _decode_recipe_list {
    my ($list) = @_;
    my @decoded;
    for my $item (@$list) {
        if (ref $item eq 'HASH') {
            if (exists $item->{c}) {
                push @decoded, $item->{c};
            } elsif (exists $item->{d}) {
                push @decoded, @{$item->{d}};
            }
            # {"z": true} is ignored — spec-04 removed it from the JSON schema
            # but §11 still uses it for truncated-body DSNs (spec inconsistency;
            # see spec-review-notes.md). Keep ignoring for backward compatibility.
        } elsif (ref $item eq 'ARRAY') {
            # Legacy bare array format — accept for backward compat
            push @decoded, $item;
        } else {
            # Legacy bare string — accept for backward compat
            push @decoded, $item;
        }
    }
    return \@decoded;
}

# --- Digests ---

sub h_digest {
    my ($msg, $alg) = @_;
    $alg = lc($alg // 'sha256');

    my $data = '';
    for my $header (sort { lc($a) cmp lc($b) } $msg->header_names) {
        next if should_skip($header);
        for my $item (reverse $msg->header_raw($header)) {
            my $chead = dkim2_canonicalize_header("$header: $item\r\n");
            warn "cdigest: $chead" if $DEBUG;
            $data .= $chead;
        }
    }

    return _hash_data_b64($alg, $data);
}

sub b_digest {
    my ($msg, $alg) = @_;
    $alg = lc($alg // 'sha256');

    # DKIM simple body canonicalization: strip trailing empty lines,
    # ensure exactly one trailing CRLF
    my $body = $msg->body_raw;
    $body =~ s/(\r\n)+\z//;
    $body .= "\r\n";

    return _hash_data_b64($alg, $body);
}

# spec-05 §3.1/§3.4: hash $data with the named (implemented) algorithm and
# base64-encode the result. Equivalent to the historic digest64($digest)
# path for sha256 (verified byte-identical), generalised to any algorithm
# in %HASH_ALGS.
sub _hash_data_b64 {
    my ($alg, $data) = @_;
    my $fn = $HASH_ALGS{$alg} or croak "unsupported hash algorithm: $alg";
    return encode_base64($fn->($data), '');
}

# --- Body recipe computation ---

# Straight line-level diff using Algorithm::Diff.
sub _body_recipe_linediff {
    my ($l1, $l2) = @_;

    my $diff = Algorithm::Diff->new($l1, $l2);
    $diff->Base(1);

    my @list;
    my $dirty = 0;
    while ($diff->Next()) {
        if ($diff->Same()) {
            push @list, [$diff->Min(1), $diff->Max(1)];
        } else {
            $dirty = 1;
            push @list, map { $_ } $diff->Items(2);
        }
    }

    return (@list > 1 || $dirty) ? \@list : undef;
}

# Build a cumulative offset table: entry i is the flat byte offset
# where line i starts.  Final entry is the total flat length.
sub _line_offsets {
    my ($lines) = @_;
    my @offsets = (0);
    for my $line (@$lines) {
        push @offsets, $offsets[-1] + length($line);
    }
    return \@offsets;
}

# Map a flat byte position to a 0-based line index.
sub _flat_to_line {
    my ($offsets, $byte_pos) = @_;
    for my $i (0 .. $#$offsets - 1) {
        return $i if $byte_pos < $offsets->[$i + 1];
    }
    return $#$offsets - 1;
}

# Build recipe entries for a region, using line-level matching.
sub _recipe_for_region {
    my ($cur_lines, $cur_start, $cur_end,
        $prev_lines, $prev_start, $prev_end) = @_;

    my @cur_region  = @{$cur_lines}[$cur_start .. $cur_end - 1];
    my @prev_region = @{$prev_lines}[$prev_start .. $prev_end - 1];

    return () unless @prev_region;
    if ("@cur_region" eq "@prev_region"
        and @cur_region == @prev_region) {
        # Check element-by-element since join could false-match.
        my $match = 1;
        for my $i (0 .. $#cur_region) {
            if ($cur_region[$i] ne $prev_region[$i]) {
                $match = 0;
                last;
            }
        }
        return ([$cur_start + 1, $cur_end]) if $match;
    }

    my $diff = Algorithm::Diff->new(\@cur_region, \@prev_region);
    $diff->Base(0);

    my @recipe;
    while ($diff->Next()) {
        if ($diff->Same()) {
            push @recipe,
                [$cur_start + $diff->Min(1) + 1,
                 $cur_start + $diff->Max(1) + 1];
        } else {
            push @recipe, $diff->Items(2);
        }
    }
    return @recipe;
}

# Estimate the wire cost of a recipe.
sub _recipe_cost {
    my ($recipe) = @_;
    return 999999 unless $recipe;
    my $cost = 0;
    for my $item (@$recipe) {
        if (ref $item eq 'ARRAY') {
            $cost += 8;    # [N, M] is cheap
        } else {
            $cost += length($item);
        }
    }
    return $cost;
}

# Byte-level prefix/suffix matching strategy.
# Flattens both bodies, finds common prefix and suffix, maps back
# to line boundaries, then uses line-level matching on the middle.
sub _body_recipe_flat {
    my ($l1, $l2) = @_;

    my $cur_flat  = join('', @$l1);
    my $prev_flat = join('', @$l2);

    # Find common prefix length.
    my $min_len = length($cur_flat) < length($prev_flat)
        ? length($cur_flat) : length($prev_flat);
    my $prefix = 0;
    while ($prefix < $min_len
           and substr($cur_flat, $prefix, 1)
               eq substr($prev_flat, $prefix, 1)) {
        $prefix++;
    }

    # Find common suffix length (not overlapping prefix).
    my $suffix = 0;
    my $max_suffix = $min_len - $prefix;
    while ($suffix < $max_suffix
           and substr($cur_flat, -1 - $suffix, 1)
               eq substr($prev_flat, -1 - $suffix, 1)) {
        $suffix++;
    }

    # If no significant prefix or suffix, this strategy won't help.
    return undef unless $prefix > 0 or $suffix > 0;

    my $cur_offsets  = _line_offsets($l1);
    my $prev_offsets = _line_offsets($l2);

    # Find last complete line within the common prefix.
    my $cur_prefix_end = 0;
    for my $i (0 .. $#$l1) {
        if ($cur_offsets->[$i + 1] <= $prefix) {
            $cur_prefix_end = $i + 1;
        } else {
            last;
        }
    }
    my $prev_prefix_end = 0;
    for my $i (0 .. $#$l2) {
        if ($prev_offsets->[$i + 1] <= $prefix) {
            $prev_prefix_end = $i + 1;
        } else {
            last;
        }
    }

    # Find first complete line within the common suffix.
    my $cur_suffix_start = scalar @$l1;
    if ($suffix > 0) {
        my $tail_start = length($cur_flat) - $suffix;
        for my $i (reverse 0 .. $#$l1) {
            if ($cur_offsets->[$i] >= $tail_start) {
                $cur_suffix_start = $i;
            } else {
                last;
            }
        }
    }
    my $prev_suffix_start = scalar @$l2;
    if ($suffix > 0) {
        my $tail_start = length($prev_flat) - $suffix;
        for my $i (reverse 0 .. $#$l2) {
            if ($prev_offsets->[$i] >= $tail_start) {
                $prev_suffix_start = $i;
            } else {
                last;
            }
        }
    }

    # Ensure suffix doesn't overlap prefix.
    $cur_suffix_start = $cur_prefix_end
        if $cur_suffix_start < $cur_prefix_end;
    $prev_suffix_start = $prev_prefix_end
        if $prev_suffix_start < $prev_prefix_end;

    # Build recipe: prefix region + middle region + suffix region.
    my @recipe;
    push @recipe, _recipe_for_region(
        $l1, 0, $cur_prefix_end,
        $l2, 0, $prev_prefix_end);
    push @recipe, _recipe_for_region(
        $l1, $cur_prefix_end, $cur_suffix_start,
        $l2, $prev_prefix_end, $prev_suffix_start);
    push @recipe, _recipe_for_region(
        $l1, $cur_suffix_start, scalar @$l1,
        $l2, $prev_suffix_start, scalar @$l2);

    return @recipe ? \@recipe : undef;
}

# --- Epilogue helpers ---

# Generate a random boundary string that is very unlikely to appear in message content.
sub _random_boundary {
    return sprintf('dkim2-epilogue-%08x%08x', int(rand(2**32)), int(rand(2**32)));
}

# Add $old_body into the MIME epilogue of $msg (an Email::MIME object),
# modifying it in place.  Returns the number of body lines that precede
# the epilogue, so the caller can build a line-range rb recipe.
#
# If $msg is already multipart, the old body is appended after the final
# MIME boundary (--BOUNDARY--).  If it is not multipart, the current
# content is wrapped in a single-part multipart/mixed container and the
# old body goes after the new final boundary.  In the wrap case the
# caller's rh header-diff will automatically record the Content-Type change.
sub _add_epilogue {
    my ($msg, $old_body) = @_;

    my $ct = $msg->content_type // '';

    if ($ct =~ m{^multipart/}i) {
        # Already multipart: append old body after the final boundary line.
        my ($boundary) = ($ct =~ /boundary="?([^";]+)"?/i);
        croak "Cannot find MIME boundary in Content-Type: $ct" unless $boundary;

        my $body  = $msg->body_raw;
        my $final = "--$boundary--";

        # Find the first (and should be only) final-boundary occurrence.
        my $idx = index($body, "$final\r\n");
        if ($idx >= 0) {
            $body = substr($body, 0, $idx + length($final) + 2) . $old_body;
        } else {
            # Tolerate bare LF or missing trailing newline.
            $idx = index($body, "$final\n");
            if ($idx >= 0) {
                $body = substr($body, 0, $idx + length($final) + 1) . $old_body;
            } else {
                $idx = index($body, $final);
                $body = ($idx >= 0 ? substr($body, 0, $idx + length($final)) : $body)
                      . "\r\n" . $old_body;
            }
        }
        $msg->body_set($body);

    } else {
        # Not multipart: wrap current content in multipart/mixed; put old body in epilogue.
        my $boundary  = _random_boundary();
        my $orig_ct   = $msg->header('Content-Type') // 'text/plain';
        my $orig_cte  = $msg->header('Content-Transfer-Encoding');
        my $orig_body = $msg->body_raw;

        my $new_body  = "--$boundary\r\n";
        $new_body    .= "Content-Type: $orig_ct\r\n";
        $new_body    .= "Content-Transfer-Encoding: $orig_cte\r\n" if $orig_cte;
        $new_body    .= "\r\n";
        $new_body    .= $orig_body;
        $new_body    .= "\r\n--$boundary--\r\n";
        $new_body    .= $old_body;

        $msg->header_set('Content-Type', "multipart/mixed; boundary=\"$boundary\"");
        $msg->header_set('Content-Transfer-Encoding') if $orig_cte;
        $msg->body_set($new_body);
    }

    # Return number of lines before the epilogue so the caller can build
    # a line-range recipe.  The old body occupies the last N lines of the
    # modified body, where N = lines in $old_body.
    my @all_lines = split /\r?\n/, $msg->body_raw;
    my @old_lines = split /\r?\n/, $old_body;
    return scalar(@all_lines) - scalar(@old_lines);  # 0-based count of prefix lines
}

# --- Calculate helpers ---

# Count literal string items in a recipe (non-array items = lines not in current body).
sub _recipe_literal_lines {
    my ($recipe) = @_;
    return 0 unless $recipe;
    return scalar grep { !ref $_ } @$recipe;
}

# Return the cheaper of the two diff strategies for two raw body strings.
# Returns undef if bodies are identical (no recipe needed).
sub _best_body_diff {
    my ($cur_raw, $prev_raw) = @_;
    (my $s1 = $cur_raw)  =~ s/[\r\n]+$//;
    (my $s2 = $prev_raw) =~ s/[\r\n]+$//;
    return undef if $s1 eq $s2;
    my @l1 = split /\r?\n/, $s1;
    my @l2 = split /\r?\n/, $s2;
    my $line = _body_recipe_linediff(\@l1, \@l2);
    my $flat = _body_recipe_flat(\@l1, \@l2);
    return undef unless $line || $flat;
    return $flat unless $line;
    return $line unless $flat;
    return _recipe_cost($flat) < _recipe_cost($line) ? $flat : $line;
}

# Store $old_body in the MIME epilogue of $current (modifying it in place),
# then return a rb line-range recipe pointing at those lines.
sub _epilogue_recipe {
    my ($current, $old_body) = @_;
    my @old_lines  = split /\r?\n/, $old_body;
    return undef unless @old_lines;
    my $prefix_len = _add_epilogue($current, $old_body);
    return [[$prefix_len + 1, $prefix_len + @old_lines]];
}

# --- Calculate ---

sub calculate {
    my ($class, $current, $previous, %opts) = @_;
    croak "need a message" unless $current;

    my $self = bless {}, $class;

    # spec-05 §3.1: the signer chooses one or more hash algorithms; default
    # is sha256 only (the signer default MUST NOT change).
    $self->{algs} = ($opts{Algs} && @{$opts{Algs}}) ? [ @{$opts{Algs}} ] : ['sha256'];

    unless (ref($current) && $current->isa('Email::MIME')) {
        $current = Email::MIME->new($current);
    }

    # $rb_recipe is determined before hash computation because epilogue
    # strategies modify $current in place, and hashes must cover the
    # final (possibly modified) message.
    my $rb_recipe;

    if ($previous) {
        unless (ref($previous) && $previous->isa('Email::MIME')) {
            $previous = Email::MIME->new($previous);
        }

        my @mi_cur = $current->header_raw('Message-Instance');
        my @mi_prev = $previous->header_raw('Message-Instance');
        die "Previous message has no existing instances" unless @mi_prev;
        # Verify same message by checking MI headers match
        # header_raw returns values only, so prepend the name for canonicalization
        my $canon_cur  = join(',', map { dkim2_canonicalize_header("Message-Instance: $_") } @mi_cur);
        my $canon_prev = join(',', map { dkim2_canonicalize_header("Message-Instance: $_") } @mi_prev);
        die "This isn't the same message" unless ($canon_cur eq $canon_prev);

        my %map = map { extract_mi_version($_) => $_ } @mi_cur;
        $self->set_tag('m', max(keys %map) + 1);

        if ($opts{UseEpilogue}) {
            # Always store old body in MIME epilogue.
            $rb_recipe = _epilogue_recipe($current, $previous->body_raw);
        }
        elsif (defined $opts{EpilogueThreshold}) {
            # Use epilogue only when the diff would exceed the threshold of
            # literal (non-range) lines.  Compute diff first (no side effects),
            # then fall back to epilogue if it is too large.
            my $diff = _best_body_diff($current->body_raw, $previous->body_raw);
            if (!defined $diff || _recipe_literal_lines($diff) > $opts{EpilogueThreshold}) {
                $rb_recipe = _epilogue_recipe($current, $previous->body_raw);
            }
            else {
                $rb_recipe = $diff;
            }
        }
        else {
            # Default: compute diff recipe (does not modify $current).
            $rb_recipe = _best_body_diff($current->body_raw, $previous->body_raw);
        }
    }
    else {
        die "Already has Message-Instance headers" if $current->header_raw('Message-Instance');
        $self->set_tag('m', 1);
    }

    # Hashes are always of the current (newest) version of the message,
    # computed after any epilogue modification, for every configured
    # algorithm (spec-05 §7.3).
    for my $alg (@{$self->{algs}}) {
        $self->{bits}{hashes}{$alg} = [ h_digest($current, $alg), b_digest($current, $alg) ];
    }
    if (my $sha256 = $self->{bits}{hashes}{sha256}) {
        @{$self->{bits}}{qw(h1 b1)} = @$sha256;
    }

    # nothing more to calculate without a previous version
    return $self unless $previous;

    # calculate the header difference (always, even for UseEpilogue, since
    # wrapping changes Content-Type and we need rh to undo that)
    my %all = map { lc($_) => 1 } ($current->header_names, $previous->header_names);
    my %hdiff;
    for my $h (sort keys %all) {
        next if should_skip($h);
        my @cur  = reverse $current->header_raw($h);
        my @prev = reverse $previous->header_raw($h);
        next if join("\n", map { dkim2_canonicalize_header($_) } @cur)
             eq join("\n", map { dkim2_canonicalize_header($_) } @prev);
        # headers are indexed from 1 from the bottom up
        my %known = map {
            dkim2_canonicalize_header($cur[$_]) => $_ + 1
        } reverse 0..$#cur;
        # Recipe: reconstruct @prev from @cur
        my @res = map {
            $known{dkim2_canonicalize_header($_)}
                ? [$known{dkim2_canonicalize_header($_)}, $known{dkim2_canonicalize_header($_)}]
                : $_
        } @prev;
        # combine adjacent ranges
        for (1..$#res) {
            next unless (ref $res[$_] && ref $res[$_-1]);
            next unless ($res[$_][0] == $res[$_-1][1] + 1);
            $res[$_][0] = $res[$_-1][0];
            $res[$_-1] = undef;
        }
        my @vals = grep { defined } @res;
        $hdiff{$h} = \@vals;
    }

    if ($rb_recipe) {
        $self->set_tag('rb', $rb_recipe);
    }
    if (keys %hdiff) {
        $self->set_tag('rh', \%hdiff);
    }

    return $self;
}

# --- Verify ---

sub verify {
    my ($class, $msg) = @_;
    croak "need a message" unless $msg;

    unless (ref($msg) && $msg->isa('Email::MIME')) {
        $msg = Email::MIME->new($msg);
    }

    my %map = map { extract_mi_version($_) => $_ } $msg->header_raw('Message-Instance');
    my $num = keys %map ? max(keys %map) : 0;
    return 0 unless $num;

    my $self = $class->parse($map{$num});

    # spec-05 §3.4: verify every hash-set whose algorithm we implement; ALL
    # of them must match. If none names an implemented algorithm, fail
    # closed rather than treating it as "no hash" -- an MI signed with only
    # sha512 (say) is perfectly valid and must verify via its sha512 set,
    # not be rejected just because h1/b1 (the sha256 alias) are undef.
    my $hashes = $self->get_tag('hashes') || {};
    my $impl = hash_algs();
    my @usable = sort grep { $impl->{$_} } keys %$hashes;

    unless (@usable) {
        return wantarray ? (0, "Message-Instance m=$num no supported hash algorithm") : 0;
    }

    for my $alg (@usable) {
        my ($h1, $b1) = @{ $hashes->{$alg} };
        my $hd = h_digest($msg, $alg);
        my $bd = b_digest($msg, $alg);
        if ($h1 ne $hd) {
            return wantarray ? (0, "$alg header hash mismatch ($h1 != $hd)") : 0;
        }
        if ($b1 ne $bd) {
            return wantarray ? (0, "$alg body hash mismatch ($b1 != $bd)") : 0;
        }
    }

    return $num;
}

# --- Undo ---

sub undo {
    my ($class, $msg) = @_;
    croak "need a message" unless $msg;

    unless (ref($msg) && $msg->isa('Email::MIME')) {
        $msg = Email::MIME->new($msg);
    }

    my %map = map { extract_mi_version($_) => $_ } $msg->header_raw('Message-Instance');
    my $num = keys %map ? max(keys %map) : 0;
    return unless $num;

    $msg->header_obj->header_filter('Message-Instance', sub { extract_mi_version(shift) < $num });

    my $self = $class->parse($map{$num});

    my $rb = $self->get_tag('rb');
    my $rh = $self->get_tag('rh');

    if ($rb) {
        my @old = split /\r?\n/, $msg->body_raw;
        my @new;
        for my $cmd (@$rb) {
            if (ref($cmd) eq 'ARRAY') {
                my ($from, $to) = ($cmd->[0] - 1, $cmd->[1] - 1);
                push @new, @old[$from..$to];
            } else {
                push @new, $cmd;
            }
        }
        $msg->body_set(join("\r\n", @new, ''));
    }

    if ($rh) {
        for my $h (sort keys %$rh) {
            my $v = $rh->{$h};
            next unless defined $v;
            my @old = reverse $msg->header_raw($h);
            my @new;
            for my $cmd (@$v) {
                if (ref($cmd) eq 'ARRAY') {
                    my ($from, $to) = ($cmd->[0] - 1, $cmd->[1] - 1);
                    push @new, @old[$from..$to];
                } else {
                    push @new, $cmd;
                }
            }
            $msg->header_obj->header_set_reverse($h, @new);
        }
    }

    return $msg;
}

# Verify the WHOLE Message-Instance chain reverses cleanly: check the top
# instance against the current content, then undo it and check the next one
# down, until m=1 or an instance that declares the previous state
# unrecoverable. This is the undo check a recipient performs — running it
# before signing catches an upstream that emitted a non-reversible recipe.
# Returns (1, undef) on success or (0, reason) on the first failure.
sub chain_verifies {
    my ($class, $msg) = @_;
    unless (ref($msg) && $msg->isa('Email::MIME')) {
        $msg = Email::MIME->new("$msg");
    }
    while (1) {
        my @mi = $msg->header_raw('Message-Instance');
        my %by_v = map { (extract_mi_version($_) // 0) => $_ } @mi;
        my $num = %by_v ? (sort { $b <=> $a } keys %by_v)[0] : 0;
        last unless $num;

        my ($ok, $err) = $class->verify($msg);
        return (0, "Message-Instance m=$num does not match content"
                 . ($err ? " ($err)" : '')) unless $ok;

        last if $num <= 1;
        my $self = $class->parse($by_v{$num});
        last if $self->unrecoverable;

        my $prev = eval { $class->undo($msg) };
        return (0, "Message-Instance m=$num did not undo cleanly"
                 . ($@ ? ": $@" : '')) if $@ || !$prev;
        $msg = $prev;
    }
    return (1, undef);
}


1;

__END__

=head1 NAME

Mail::DKIM2::MessageInstance - Calculate, verify, and undo Message-Instance headers

=head1 SYNOPSIS

    use Mail::DKIM2::MessageInstance;

    # Calculate MI for the initial message (v=1)
    my $mi = Mail::DKIM2::MessageInstance->calculate($msg);
    print "Message-Instance: " . $mi->as_string . "\n";

    # Calculate MI with diff recipes between two versions
    my $mi = Mail::DKIM2::MessageInstance->calculate($msg_current, $msg_prev);

    # Verify the highest MI header matches the message
    my $version = Mail::DKIM2::MessageInstance->verify($msg);
    # or in list context:
    my ($version, $error) = Mail::DKIM2::MessageInstance->verify($msg);

    # Undo the highest MI to recover the previous message version
    my $prev_msg = Mail::DKIM2::MessageInstance->undo($msg);

=head1 DESCRIPTION

This module implements Message-Instance header computation as defined in
draft-ietf-dkim-dkim2-spec-04.  A Message-Instance header records cryptographic
hashes of the message headers and body at a point in the delivery chain, along
with optional diff recipes that allow undoing changes made at each hop.

The wire format is: C<< v=N; h=<base64json>; r=<base64json> >>

B<EXPERIMENTAL> — This module implements an Internet-Draft that has not yet
been published as an RFC.  The API and wire format are subject to change.
Do not use in production.

=head1 CLASS METHODS

=head2 calculate($msg)

=head2 calculate($msg_current, $msg_previous)

=head2 calculate($msg_current, $msg_previous, UseEpilogue => 1)

=head2 calculate($msg_current, $msg_previous, EpilogueThreshold => N)

Creates a new MessageInstance object by computing hashes of the current message
(an L<Email::MIME> object or raw message string).  If a single message is given,
it must not already have Message-Instance headers and produces a C<v=1> entry.

With two messages, computes diff recipes (header and body) that allow
reconstruction of C<$msg_previous> from C<$msg_current>, producing the next
version number.  The hashes recorded are of C<$msg_current>.

With C<UseEpilogue =E<gt> 1>, the previous message body is always stored in the
MIME epilogue rather than encoded as a diff in the MI header.

With C<EpilogueThreshold =E<gt> N>, the best diff recipe is computed first.  If
it contains more than C<N> literal (non-range) lines, the epilogue strategy is
used instead; otherwise the diff is used.  C<N = 5> is a reasonable value
that keeps MI headers small while avoiding the epilogue overhead for small
changes.  To always use the diff, simply omit both options (the default).

For both epilogue options: if C<$msg_current> is already C<multipart/*>, the
previous body is appended after the final MIME boundary (C<--BOUNDARY--\r\n>).
If it is not multipart, the current content is wrapped in a C<multipart/mixed>
single-part container and the previous body follows the new final boundary.

The returned MI uses the standard C<rb> line-range recipe (the old body
occupies specific numbered lines of the modified body), so C<undo()> works
without any special-case logic.  The header diff (C<rh>) automatically
captures the C<Content-Type> change when wrapping occurs.

B<Note:> C<UseEpilogue> and C<EpilogueThreshold> (when epilogue is chosen)
modify C<$msg_current> in place.  Hashes are computed after modification and
cover the complete transmitted message.

=head2 verify($msg)

Verifies that the highest-versioned Message-Instance header on C<$msg> matches
the current message content.  Returns the version number on success.  In list
context, returns C<(0, $error_message)> on failure; in scalar context returns
0 on failure.

=head2 undo($msg)

Applies the recipes from the highest Message-Instance header to reverse the
message to its previous version.  Returns the modified L<Email::MIME> object,
or undef if no MI headers exist.

Handles both diff-based and epilogue-based recipes.  Epilogue-based MIs use
the same C<rb> line-range format: the old body occupies the tail lines of the
modified body, so C<undo()> extracts them via the standard range mechanism and
C<rh> restores any header changes (such as C<Content-Type> when wrapping was
used).

=head2 parse($header_value)

Parses a Message-Instance header value string into an object.  Handles both
the current C<-08> format (C<h=> and C<r=> tags) and the legacy C<-06> format
(C<j=> tag).

=head1 INSTANCE METHODS

=head2 as_string()

Serializes the MessageInstance to its wire format string.

=head2 set_tag($key, $value)

=head2 get_tag($key)

Low-level accessors for the internal tag store.  Common tags: C<v> (version),
C<h1> (header hash), C<b1> (body hash), C<rh> (header recipes), C<rb> (body
recipes).

=head1 FUNCTIONS

=head2 h_digest($email_mime)

Computes the SHA-256 header digest of an L<Email::MIME> message, using DKIM2
canonicalization and sorted header order.  Returns a base64-encoded string.

=head2 b_digest($email_mime)

Computes the SHA-256 body digest of an L<Email::MIME> message using DKIM
simple body canonicalization.  Returns a base64-encoded string.

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
