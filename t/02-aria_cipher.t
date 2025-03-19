use strict;
use warnings;
use Test2::V0;

plan(3); # run 1 test

my $testname = "02-aria_cipher";
my $count;

subtest('aria256', \&cipher_test,
        -name => 'aria256',
        -mname => 'maria256',
        -cleartext => "The quick brown fox jumps over the lazy dog",
	-ciphertext => "The quick brown fox jumps over the lazy dog",
	-keylen => '32',
        -key => 'DEADBEEF' x 8,
	-iv => 'DEADCAFE' x 4);
subtest('aria192', \&cipher_test,
        -name => 'aria192',
        -mname => 'maria192',
        -cleartext => "The quick brown fox jumps over the lazy dog",
	-ciphertext => "The quick brown fox jumps over the lazy dog",
	-keylen => '24',
        -key => 'DEADBEEF' x 6,
	-iv => 'DEADCAFE' x 4);
subtest('aria128', \&cipher_test,
        -name => 'aria128',
        -mname => 'maria128',
        -cleartext => "The quick brown fox jumps over the lazy dog",
	-ciphertext => "The quick brown fox jumps over the lazy dog",
	-keylen => '16',
        -key => 'DEADBEEF' x 4,
	-iv => 'DEADCAFE' x 4);
sub cipher_test {
    my %opts = @_;

    plan (8);  # run 8 tests

    my $cleartextfile = "$testname-count.txt";
    open my $fclear, '>', $cleartextfile;
    print $fclear $opts{-cleartext};
    close $fclear;

    my $enccmd =
        "openssl enc -e -$opts{-name} -K $opts{-key} -iv $opts{-iv} -in $cleartextfile";
    my $enctext = `$enccmd`;
    is($?, 0,                                     "encrypting with '$enccmd'");

    my $ciphertextfile = "$testname-count.dat";
    open my $fcipher, '>', $ciphertextfile;
    print $fcipher $enctext;
    close $fcipher;

    my $deccmd0 =
        "openssl enc -d -$opts{-name} -K $opts{-key} -iv $opts{-iv} -in $ciphertextfile";
    my $dectext0 = `$deccmd0`;
    is($?, 0,                                     "decrypting with '$deccmd0'");
    is($dectext0, $opts{-cleartext}, "decryption result (default)");

    my $deccmd =
        "openssl enc -provider ariacipher -d -$opts{-mname} -K $opts{-key} -iv $opts{-iv} -in $ciphertextfile";
    my $dectext = `$deccmd`;
    is($?, 0,                                     "decrypting with '$deccmd'");
    is($dectext, $opts{-cleartext}, "decryption result (aria after default)");

    my $enccmd2 =
        "openssl enc -provider ariacipher -e -$opts{-mname} -K $opts{-key} -iv $opts{-iv} -in $cleartextfile";
    my $enctext2 = `$enccmd2`;
    is($?, 0,                                     "encrypting with '$enccmd2'");

    my $ciphertextfile2 = "$testname-count2.dat";
    open my $fcipher2, '>', $ciphertextfile2;
    print $fcipher2 $enctext2;
    close $fcipher2;

    my $deccmd2 =
        "openssl enc -d -$opts{-name} -K $opts{-key} -iv $opts{-iv} -in $ciphertextfile";
    my $dectext2 = `$deccmd2`;
    is($?, 0,                                     "decrypting with '$deccmd2'");
    is($dectext2, $opts{-cleartext}, "decryption result (default after aria)");
}
