# ldns-zonediff

Copyright (c) 2018 SURFnet bv
http://www.surf.nl/en/about-surf/subsidiaries/surfnet

All rights reserved. This tool is distributed under a BSD-style license. For more information, see LICENSE

## 1. INTRODUCTION

This tool can compute the difference between two DNS zone files and outputs the
result to the standard output. By default, it will ignore DNSSEC records.

## 2. PREREQUISITES

Building `ldns-zonediff`, requires the following dependencies to be installed:

 - POSIX-compliant build system
 - make
 - libldns >= 1.6.17
 - OpenSSL >= 1.0.1

**On Ubuntu,** you may find `libldns-dev` lacking `ldns-config`, and possibly more.
You can repackage ldns with `contrib/pkg-ldns.sh` before building.  This script
additionally requires

  - debhelper (for Ubuntu)
  - dpkg-dev (for Ubuntu)
  - dh-make (for Ubuntu)

## 3. BUILDING

To build `ldns-zonediff` fresh from the repository, execute the following commands:

    make

## 4. USING THE TOOL

The tool basically takes two zone files as input and will output the
differences between the two zones. In standard mode, it will ignore DNSSEC
records, such as keys, signatures and authenticated denial-of-existence
records. For more information on other options, please run:

    ldns-zonediff -h

# 5. CONTACT

Questions/remarks/suggestions/praise on this tool can be sent to:

Roland van Rijswijk-Deij <roland.vanrijswijk@surfnet.nl>
