#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
# Copyright 2017 BaishanCloud. All rights reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test::Simple;
use OpenSSL::Test;
use OpenSSL::Test::Utils qw(alldisabled available_protocols);

setup("test_servername");

plan skip_all => "No TLS/SSL protocols are supported by this OpenSSL build"
    if alldisabled(grep { $_ ne "ssl3" } available_protocols("tls"));

simple_test("test_servername", "servername_test");
