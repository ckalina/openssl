#! /usr/bin/env perl
# Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Generate progs.h file by looking for command mains in list of C files
# passed on the command line.

use strict;
use warnings;
use lib '.';
use configdata qw/@disablables %unified_info/;

my $opt          = shift @ARGV;
die "Unrecognised option, must be -C or -H\n"
    unless ($opt eq '-H' || $opt eq '-C');

my %commands     = ();
my $cmdre        = qr/^\s*int\s+([a-z_][a-z0-9_]*)_main\(\s*int\s+argc\s*,/;
my $apps_openssl = shift @ARGV;
my $YEAR         = [localtime()]->[5] + 1900;

# because the program apps/openssl has object files as sources, and
# they then have the corresponding C files as source, we need to chain
# the lookups in %unified_info
my @openssl_source =
    map { @{$unified_info{sources}->{$_}} }
    grep { /\.o$/ }
        @{$unified_info{sources}->{$apps_openssl}};

foreach my $filename (@openssl_source) {
    open F, $filename or die "Couldn't open $filename: $!\n";
    foreach ( grep /$cmdre/, <F> ) {
        my @foo = /$cmdre/;
        $commands{$1} = 1;
    }
    close F;
}

@ARGV = sort keys %commands;

if ($opt eq '-H') {
    print <<"EOF";
/*
 * WARNING: do not edit!
 * Generated by apps/progs.pl
 *
 * Copyright 1995-$YEAR The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "function.h"

EOF

    foreach (@ARGV) {
        printf "extern int %s_main(int argc, char *argv[]);\n", $_;
    }
    print "\n";

    foreach (@ARGV) {
        printf "extern const OPTIONS %s_options[];\n", $_;
    }
    print "\n";
    print "extern FUNCTION functions[];\n";
}

if ($opt eq '-C') {
    print <<"EOF";
/*
 * WARNING: do not edit!
 * Generated by apps/progs.pl
 *
 * Copyright 1995-$YEAR The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "progs.h"

EOF

    my %cmd_disabler = (
        ciphers  => "sock",
        pkcs12   => "des",
    );
    my %cmd_deprecated = (
        rsa      => [ "3_0", "pkey",      "rsa" ],
        genrsa   => [ "3_0", "genpkey",   "rsa" ],
        rsautl   => [ "3_0", "pkeyutl",   "rsa" ],
        dhparam  => [ "3_0", "pkeyparam", "dh" ],
        dsaparam => [ "3_0", "pkeyparam", "dsa" ],
        dsa      => [ "3_0", "pkey",      "dsa" ],
        gendsa   => [ "3_0", "genpkey",   "dsa" ],
        ec       => [ "3_0", "pkey",      "ec" ],
        ecparam  => [ "3_0", "pkeyparam", "ec" ],
    );

    print "FUNCTION functions[] = {\n";
    foreach my $cmd ( @ARGV ) {
        my $str =
            "    {FT_general, \"$cmd\", ${cmd}_main, ${cmd}_options, NULL},\n";
        if ($cmd =~ /^s_/) {
            print "#ifndef OPENSSL_NO_SOCK\n${str}#endif\n";
        } elsif (my $deprecated = $cmd_deprecated{$cmd}) {
            my @dep = @{$deprecated};
            print "#if ";
            if ($dep[2]) {
                print "!defined(OPENSSL_NO_" . uc($dep[2]) . ") && ";
            }
            print "!defined(OPENSSL_NO_DEPRECATED_" . $dep[0] . ")";
            my $dalt = "\"" . $dep[1] . "\"";
            $str =~ s/NULL/$dalt/;
            print "\n${str}#endif\n";
        } elsif (grep { $cmd eq $_ } @disablables) {
            print "#ifndef OPENSSL_NO_" . uc($cmd) . "\n${str}#endif\n";
        } elsif (my $disabler = $cmd_disabler{$cmd}) {
            print "#ifndef OPENSSL_NO_" . uc($disabler) . "\n${str}#endif\n";
        } else {
            print $str;
        }
    }

    my %md_disabler = (
        blake2b512 => "blake2",
        blake2s256 => "blake2",
    );
    foreach my $cmd (
        "md2", "md4", "md5",
        "gost",
        "sha1", "sha224", "sha256", "sha384",
        "sha512", "sha512-224", "sha512-256",
        "sha3-224", "sha3-256", "sha3-384", "sha3-512",
        "shake128", "shake256",
        "mdc2", "rmd160", "blake2b512", "blake2s256",
        "argon2i", "argon2d", "argon2id",
        "sm3"
    ) {
        my $str = "    {FT_md, \"$cmd\", dgst_main, NULL, NULL},\n";
        if (grep { $cmd eq $_ } @disablables) {
            print "#ifndef OPENSSL_NO_" . uc($cmd) . "\n${str}#endif\n";
        } elsif (my $disabler = $md_disabler{$cmd}) {
            print "#ifndef OPENSSL_NO_" . uc($disabler) . "\n${str}#endif\n";
        } else {
            print $str;
        }
    }

    my %cipher_disabler = (
        des3  => "des",
        desx  => "des",
        cast5 => "cast",
    );
    foreach my $cmd (
        "aes-128-cbc", "aes-128-ecb",
        "aes-192-cbc", "aes-192-ecb",
        "aes-256-cbc", "aes-256-ecb",
        "aria-128-cbc", "aria-128-cfb",
        "aria-128-ctr", "aria-128-ecb", "aria-128-ofb",
        "aria-128-cfb1", "aria-128-cfb8",
        "aria-192-cbc", "aria-192-cfb",
        "aria-192-ctr", "aria-192-ecb", "aria-192-ofb",
        "aria-192-cfb1", "aria-192-cfb8",
        "aria-256-cbc", "aria-256-cfb",
        "aria-256-ctr", "aria-256-ecb", "aria-256-ofb",
        "aria-256-cfb1", "aria-256-cfb8",
        "camellia-128-cbc", "camellia-128-ecb",
        "camellia-192-cbc", "camellia-192-ecb",
        "camellia-256-cbc", "camellia-256-ecb",
        "base64", "zlib",
        "des", "des3", "desx", "idea", "seed", "rc4", "rc4-40",
        "rc2", "bf", "cast", "rc5",
        "des-ecb", "des-ede", "des-ede3",
        "des-cbc", "des-ede-cbc","des-ede3-cbc",
        "des-cfb", "des-ede-cfb","des-ede3-cfb",
        "des-ofb", "des-ede-ofb","des-ede3-ofb",
        "idea-cbc","idea-ecb", "idea-cfb", "idea-ofb",
        "seed-cbc","seed-ecb", "seed-cfb", "seed-ofb",
        "rc2-cbc", "rc2-ecb", "rc2-cfb","rc2-ofb", "rc2-64-cbc", "rc2-40-cbc",
        "bf-cbc", "bf-ecb", "bf-cfb", "bf-ofb",
        "cast5-cbc","cast5-ecb", "cast5-cfb","cast5-ofb",
        "cast-cbc", "rc5-cbc", "rc5-ecb", "rc5-cfb", "rc5-ofb",
        "sm4-cbc", "sm4-ecb", "sm4-cfb", "sm4-ofb", "sm4-ctr"
    ) {
        my $str = "    {FT_cipher, \"$cmd\", enc_main, enc_options, NULL},\n";
        (my $algo = $cmd) =~ s/-.*//g;
        if ($cmd eq "zlib") {
            print "#ifdef ZLIB\n${str}#endif\n";
        } elsif (grep { $algo eq $_ } @disablables) {
            print "#ifndef OPENSSL_NO_" . uc($algo) . "\n${str}#endif\n";
        } elsif (my $disabler = $cipher_disabler{$algo}) {
            print "#ifndef OPENSSL_NO_" . uc($disabler) . "\n${str}#endif\n";
        } else {
            print $str;
        }
    }

    print "    {0, NULL, NULL, NULL, NULL}\n};\n";
}
