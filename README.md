# ldns-mergezone

Copyright (c) 2018 SURFnet bv
http://www.surf.nl/en/about-surf/subsidiaries/surfnet

All rights reserved. This tool is distributed under a BSD-style license. For more information, see LICENSE

## 1. INTRODUCTION

This tool provides a simple interface 

## 2. PREREQUISITES

Building `ldns-mergezone`, requires the following dependencies to be installed:

 - POSIX-compliant build system
 - make
 - libldns >= 1.6.17
 - OpenSSL >= 1.0.1

## 3. BUILDING

To build `ldns-mergezone` fresh from the repository, execute the following commands:

    make

## 4. USING THE TOOL

The tool basically takes two zone files as input and will output the
differences between the two zones. In standard mode, it will ignore DNSSEC
records, such as keys, signatures and authenticated denial-of-existence
records. For more information on other options, please run:

    ldns-mergezone -h

# 5. CONTACT

Questions/remarks/suggestions/praise on this tool can be sent to:

Roland van Rijswijk-Deij <roland.vanrijswijk@surfnet.nl>
