use strict;
use warnings;
use Test2::V0;

plan(1); # run 1 test

my $testname = "01-null_cipher";
my $count;

subtest('null cipher', \&cipher_test,
        -cleartext => "The quick brown fox jumps over the lazy dog",
	-ciphertext => "The quick brown fox jumps over the lazy dog",
        -key => 'DEADBEEF');

sub cipher_test {
    my %opts = @_;

    plan (3);  # run 4 tests

    my $cleartextfile = "$testname-count.txt";
    open my $fclear, '>', $cleartextfile;
    print $fclear $opts{-cleartext};
    close $fclear;

    my $enccmd =
        "openssl enc -provider nullcipher -e -null -K $opts{-key} -in $cleartextfile";
    my $enctext = `$enccmd`;
    is($?, 0,                                     "encrypting with '$enccmd'");

    my $ciphertextfile = "$testname-count.dat";
    open my $fcipher, '>', $ciphertextfile;
    print $fcipher $enctext;
    close $fcipher;

    my $deccmd =
        "openssl enc -provider nullcipher -d -null -K $opts{-key} -in $ciphertextfile";
    my $dectext = `$deccmd`;
    is($?, 0,                                     "decrypting with '$deccmd'");
    is($dectext, $opts{-cleartext}, "decryption result");
}
