#!perl

use 5.010001;
use strict;
use warnings;
use Test::More 0.98;

use Bitcoin::BIP39 qw(
                         entropy_to_bip39_mnemonic
                         bip39_mnemonic_to_entropy
                         gen_bip39_mnemonic
                 );

subtest bip39_mnemonic_to_entropy => sub {
    is(bip39_mnemonic_to_entropy(mnemonic => "stomach insane welcome steel squirrel wise noodle index truck meadow guitar exchange", encoding=>"hex"), "d62e9fe56a9d3bf8e58396e931359f27");
    # XXX test encoding=undef
    # XXX test invalid mnemonic
};

subtest entropy_to_bip39_mnemonic => sub {
    is(entropy_to_bip39_mnemonic(entropy_hex => "d62e9fe56a9d3bf8e58396e931359f27"), "stomach insane welcome steel squirrel wise noodle index truck meadow guitar exchange");
    # XXX test inputting entropy
};

subtest gen_bip39_mnemonic => sub {
    ok(gen_bip39_mnemonic());
};

DONE_TESTING:
done_testing;
