#! /usr/bin/env perl
# Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use integer;
use strict;
use warnings;

# Generate the DER encoding for the given OID.
sub der_it
{
    # Prologue
    my ($v) = @_;
    my @a = split(/\s+/, $v);
    my $ret = pack("C*", $a[0] * 40 + $a[1]);
    shift @a;
    shift @a;

    # Loop over rest of bytes; or in 0x80 for multi-byte numbers.
    my $t;
    foreach (@a) {
        my @r = ();
        $t = 0;
        while ($_ >= 128) {
            my $x = $_ % 128;
            $_ /= 128;
            push(@r, ($t++ ? 0x80 : 0) | $x);
        }
        push(@r, ($t++ ? 0x80 : 0) | $_);
        $ret .= pack("C*", reverse(@r));
    }
    return $ret;
}

# Output year depends on the year of the script and the input file.
my $YEAR = [localtime([stat($0)]->[9])]->[5] + 1900;
my $iYEAR = [localtime([stat($ARGV[0])]->[9])]->[5] + 1900;
$YEAR = $iYEAR if $iYEAR > $YEAR;

# Read input, parse all #define's into OID name and value.
# Populate %ln and %sn with long and short names (%dupln and %dupsn)
# are used to watch for duplicates.  Also %nid and %obj get the
# NID and OBJ entries.
my %ln;
my %sn;
my %dupln;
my %dupsn;
my %nid;
my %obj;
my %objd;
open(IN, "$ARGV[0]") || die "Can't open input file $ARGV[0], $!";
while (<IN>) {
    next unless /^\#define\s+(\S+)\s+(.*)$/;
    my $v = $1;
    my $d = $2;
    $d =~ s/^\"//;
    $d =~ s/\"$//;
    if ($v =~ /^SN_(.*)$/) {
        if (defined $dupsn{$d}) {
            print "WARNING: Duplicate short name \"$d\"\n";
        } else {
            $dupsn{$d} = 1;
        }
        $sn{$1} = $d;
    }
    elsif ($v =~ /^LN_(.*)$/) {
        if (defined $dupln{$d}) {
            print "WARNING: Duplicate long name \"$d\"\n";
        } else {
            $dupln{$d} = 1;
        }
        $ln{$1} = $d;
    }
    elsif ($v =~ /^NID_(.*)$/) {
        $nid{$d} = $1;
    }
    elsif ($v =~ /^OBJ_(.*)$/) {
        $obj{$1} = $v;
        $objd{$v} = $d;
    }
}
close IN;

# For every value in %obj, recursively expand OBJ_xxx values.  That is:
#     #define OBJ_iso 1L
#     #define OBJ_identified_organization OBJ_iso,3L
# Modify %objd values in-place.  Create an %objn array that has
my $changed;
do {
    $changed = 0;
    foreach my $k (keys %objd) {
        $changed = 1 if $objd{$k} =~ s/(OBJ_[^,]+),/$objd{$1},/;
    }
} while ($changed);

my @a = sort { $a <=> $b } keys %nid;
my $n = $a[$#a] + 1;
my @lvalues = ();
my $lvalues = 0;

# Scan all defined objects, building up the @out array.
# %obj_der holds the DER encoding as an array of bytes, and %obj_len
# holds the length in bytes.
my @out;
my %obj_der;
my %obj_len;
for (my $i = 0; $i < $n; $i++) {
    if (!defined $nid{$i}) {
        push(@out, "    { NULL, NULL, NID_undef },\n");
        next;
    }

    my $sn = defined $sn{$nid{$i}} ? "$sn{$nid{$i}}" : "NULL";
    my $ln = defined $ln{$nid{$i}} ? "$ln{$nid{$i}}" : "NULL";
    if ($sn eq "NULL") {
        $sn = $ln;
        $sn{$nid{$i}} = $ln;
    }
    if ($ln eq "NULL") {
        $ln = $sn;
        $ln{$nid{$i}} = $sn;
    }

    my $out = "    {\"$sn\", \"$ln\", NID_$nid{$i}";
    if (defined $obj{$nid{$i}} && $objd{$obj{$nid{$i}}} =~ /,/) {
        my $v = $objd{$obj{$nid{$i}}};
        $v =~ s/L//g;
        $v =~ s/,/ /g;
        my $r = &der_it($v);
        my $z = "";
        my $length = 0;
        # Format using fixed-with because we use strcmp later.
        foreach (unpack("C*",$r)) {
            $z .= sprintf("0x%02X,", $_);
            $length++;
        }
        $obj_der{$obj{$nid{$i}}} = $z;
        $obj_len{$obj{$nid{$i}}} = $length;

        push(@lvalues,
            sprintf("    %-45s  /* [%5d] %s */\n",
                $z, $lvalues, $obj{$nid{$i}}));
        $out .= ", $length, &so[$lvalues]";
        $lvalues += $length;
    }
    $out .= "},\n";
    push(@out, $out);
}

# Finally ready to generate the output.
open(OUT, ">$ARGV[1]") || die "Can't open output file $ARGV[1], $!";
print OUT <<"EOF";
/*
 * WARNING: do not edit!
 * Generated by crypto/objects/obj_dat.pl
 *
 * Copyright 1995-$YEAR The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

EOF

print OUT "/* Serialized OID's */\n";
printf OUT "static const unsigned char so[%d] = {\n", $lvalues + 1;
print OUT @lvalues;
print OUT "};\n\n";

printf OUT "#define NUM_NID %d\n", $n;
printf OUT "static const ASN1_OBJECT nid_objs[NUM_NID] = {\n";
print OUT @out;
print  OUT "};\n\n";

{
    no warnings "uninitialized";
    @a = grep(defined $sn{$nid{$_}}, 0 .. $n);
}
printf OUT "#define NUM_SN %d\n", $#a + 1;
printf OUT "static const unsigned int sn_objs[NUM_SN] = {\n";
foreach (sort { $sn{$nid{$a}} cmp $sn{$nid{$b}} } @a) {
    printf OUT "    %4d,    /* \"$sn{$nid{$_}}\" */\n", $_;
}
print  OUT "};\n\n";

{
    no warnings "uninitialized";
    @a = grep(defined $ln{$nid{$_}}, 0 .. $n);
}
printf OUT "#define NUM_LN %d\n", $#a + 1;
printf OUT "static const unsigned int ln_objs[NUM_LN] = {\n";
foreach (sort { $ln{$nid{$a}} cmp $ln{$nid{$b}} } @a) {
    printf OUT "    %4d,    /* \"$ln{$nid{$_}}\" */\n", $_;
}
print  OUT "};\n\n";

{
    no warnings "uninitialized";
    @a = grep(defined $obj{$nid{$_}}, 0 .. $n);
}
printf OUT "#define NUM_OBJ %d\n", $#a + 1;
printf OUT "static const unsigned int obj_objs[NUM_OBJ] = {\n";

# Compare DER; prefer shorter; if some length, use the "smaller" encoding.
sub obj_cmp
{
    no warnings "uninitialized";
    my $A = $obj_len{$obj{$nid{$a}}};
    my $B = $obj_len{$obj{$nid{$b}}};
    my $r = $A - $B;
    return $r if $r != 0;

    $A = $obj_der{$obj{$nid{$a}}};
    $B = $obj_der{$obj{$nid{$b}}};
    return $A cmp $B;
}
foreach (sort obj_cmp @a) {
    my $m = $obj{$nid{$_}};
    my $v = $objd{$m};
    $v =~ s/L//g;
    $v =~ s/,/ /g;
    printf OUT "    %4d,    /* %-32s %s */\n", $_, $m, $v;
}
print  OUT "};\n";

close OUT;
