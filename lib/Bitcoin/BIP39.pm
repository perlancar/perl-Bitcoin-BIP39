package Bitcoin::BIP39;

# DATE
# VERSION

use 5.010001;
use strict;
use warnings;

use Exporter qw(import);
our @EXPORT_OK = qw(
                       entropy_to_bip39_mnemonic
                       bip39_mnemonic_to_entropy
                       gen_bip39_mnemonic
               );

our %SPEC;

my %all_words_cache; # key = module name, value = \@wordlist

our %arg_language = (
    language => {
        summary => 'Pick which language wordlist to use',
        schema => ['str*', match=>qr/\A\w{2}(?:-\w+)?\z/],
        default => 'en',
        description => <<'_',

Will retrieve wordlist from `WordList::<LANG_CODE>::BIP39` Perl module.

For Chinese (simplified), use `zh-simplified`. For Chinese (traditional), use
`zh-traditional`.

_
    },
);

our %arg0_mnemonic = (
    mnemonic => {
        summary => 'Mnemonic phrase',
        schema => ['str*'],
        pos => 0,
    },
);

our %arg_bits = (
    bits => {
        summary => 'Size of entropy in bits',
        schema => ['posint*', in=>[128, 160, 192, 224, 256]],
        default => 128,
    },
);

our %args_entropy = (
    entropy => {
        summary => 'Entropy (binary data)',
        schema => ['buf*'],
    },
    entropy_hex => {
        summary => 'Entropy (hex-encoded)',
        schema => ['hexbuf*'],
        pos => 0,
    },
);

our %arg_encoding = (
    encoding => {
        schema => ['str', in=>"hex"],
        default => 'hex',
    },
);

sub _get_all_words {
    my $language = shift // 'en';

    my ($langcode, $variant) = $language =~ /\A(\w{2})(?:-(\w+))?\z/
        or die "Invalid language '$language', please specify a ".
        "2-digit language code";
    my $mod = "WordList::".uc($langcode).
        ($variant ? "::".ucfirst(lc($variant)) : "")."::BIP39";
    if ($all_words_cache{$mod}) {
        return $all_words_cache{$mod};
    }
    (my $mod_pm = "$mod.pm") =~ s!::!/!g;
    require $mod_pm;
    return ($all_words_cache{$mod} = [$mod->new->all_words]);
}

$SPEC{entropy_to_bip39_mnemonic} = {
    v => 1.1,
    summary => 'Convert entropy to BIP39 mnemonic phrase',
    args => {
        %arg_language,
        %args_entropy,
    },
    args_rels => {
        req_one => ['entropy', 'entropy_hex'],
    },
};
sub entropy_to_bip39_mnemonic {
    require Digest::SHA;

    my %args = @_;

    my $entropy;
    if (defined $args{entropy}) {
        $entropy = $args{entropy};
    } elsif (defined $args{entropy_hex}) {
        $entropy = pack("H*", $args{entropy_hex});
    } else {
        die "Please specify entropy/entropy_hex";
    }

    my $bits = length($entropy) * 8;
    unless ($bits == 128 || $bits == 160 || $bits == 192 ||
                $bits == 224 || $bits == 256) {
        die "Sorry, bits=$bits not yet supported";
    }

    my $bits_chksum = $bits / 32;
    my $num_words   = ($bits + $bits_chksum) / 11; # in number of words

    my $all_words = _get_all_words($args{language});

    my $chksum = Digest::SHA::sha256($entropy);

    my $bitstr = unpack("B*", $entropy) . unpack("B$bits_chksum", $chksum);
    #say "D:bitstr=<$bitstr>";
    my @words;
    while ($bitstr =~ /(.{11})/g) {
        my $index = unpack("n", pack("B*", "00000$1"));
        #say "D:index = <$index>";
        push @words, $all_words->[$index];
    }
    join " ", @words;
}

$SPEC{bip39_mnemonic_to_entropy} = {
    v => 1.1,
    summary => 'Convert BIP39 mnemonic phrase to entropy',
    args => {
        %arg0_mnemonic,
        %arg_language,
        %arg_encoding,
    },
    args_rels => {
        req_one => ['entropy', 'entropy_hex'],
    },
};
sub bip39_mnemonic_to_entropy {
    require Digest::SHA;

    my %args = @_;

    my $all_words = _get_all_words($args{language});

    my @words = split /\s+/, lc($args{mnemonic});
    my ($bits, $bits_chksum);
    if (@words == 12) {
        ($bits, $bits_chksum) = (128, 4);
    } elsif (@words == 15) {
        ($bits, $bits_chksum) = (160, 5);
    } elsif (@words == 18) {
        ($bits, $bits_chksum) = (192, 6);
    } elsif (@words == 21) {
        ($bits, $bits_chksum) = (224, 7);
    } elsif (@words == 24) {
        ($bits, $bits_chksum) = (256, 8);
    } else {
        die "Invalid number of words, must be 12/15/18/21/24";
    }

    my @indices;
  WORD:
    for my $word (@words) {
        # XXX use binary search
        for my $idx (0..$#{$all_words}) {
            if ($word eq $all_words->[$idx]) {
                push @indices, $idx;
                next WORD;
            }
        }
        die "Word '$word' not found in wordlist";
    }

    my $bitstr = "";
    for my $idx (@indices) {
        my $b = unpack("B*", pack("n", $idx));
        $bitstr .= substr($b, 5);
    }
    #say "D:bitstr=<$bitstr>";

    my $entropy = pack("B*", substr($bitstr, 0, $bits));
    #say "D:entropy_hex=", unpack("H*", $entropy);
    my $chksum  = substr($bitstr, $bits);
    #say "D:chksum=<$chksum>";

    my $real_chksum = Digest::SHA::sha256($entropy);
    #say "D:real_chksum=", unpack("B$bits_chksum", $real_chksum);
    unless ($chksum eq unpack("B$bits_chksum", $real_chksum)) {
        die "Invalid mnemonic (checksum doesn't match)";
    }

    if ($args{encoding} && $args{encoding} eq 'hex') {
        return unpack("H*", $entropy);
    } else {
        return $entropy;
    }
}

$SPEC{gen_bip39_mnemonic} = {
    v => 1.1,
    summary => 'Generate BIP39 mnemonic phrase',
    args => {
        %arg_language,
        %arg_bits,
    },
};
sub gen_bip39_mnemonic {
    require Bytes::Random::Secure;

    my %args = @_;

    my $bits = $args{bits} // 128;
    $bits % 8 and die "Please specify bits that are divisible by 8";
    my $entropy = Bytes::Random::Secure::random_bytes($bits / 8);

    my $mnemonic = entropy_to_bip39_mnemonic(
        entropy => $entropy,
        (language => $args{language}) x !!defined($args{language}),
    );

    return {
        mnemonic => $mnemonic,
        entropy_hex => unpack("H*", $entropy),
    };
}

1;
# ABSTRACT: A BIP39 implementation in Perl

=head1 DESCRIPTION

This module is an implementation of BIP39 (mnemonic phrase). Features:

=over

=item * Ability to choose non-English wordlist

As long as the appropriate C<< WordList::<LANG_CODE>::BIP39 >> module exists.

=back

=head2 TODO

=over

=item * Allow mispellings after the 4th character

=item * Language detection

=back


=head1 SEE ALSO

L<https://en.bitcoin.it/wiki/Mnemonic_phrase>

L<https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>

=cut
