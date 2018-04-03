#!/bin/bash
#
# Script to create a dpkg for libldns
LDNS_URL="https://www.nlnetlabs.nl/downloads/ldns/ldns-1.7.0.tar.gz"
LDNS_TAR="ldns-1.7.0.tar.gz"
LDNS_DIR="ldns-1.7.0"
LDNS_PATCHED_TAR="ldns-1.7.0.tar.gz"
LDNS_PATCHED_DIR="ldns-1.7.0"

HERE=`pwd`

cd /tmp
mkdir ldnspkg-$$
cd ldnspkg-$$

wget $LDNS_URL

if [ ! -s $LDNS_TAR ] ; then
	echo "Failed to download LDNS tarball"
	exit 1
fi

tar zxvf $LDNS_TAR

cd $LDNS_DIR

mkdir -p doc/man/man3
touch doc/man/man3/intentionally-blank

cd ..

mv $LDNS_DIR $LDNS_PATCHED_DIR

tar -zcvf $LDNS_PATCHED_TAR $LDNS_PATCHED_DIR

cd $LDNS_PATCHED_DIR

dh_make -y --single --copyright bsd -e dns-beheer@surfnet.nl -f ../$LDNS_PATCHED_TAR

# New: turn off DANE validation
cat >> debian/rules <<EOF

override_dh_auto_configure:
	dh_auto_configure -- --disable-dane-verify
EOF

dch -i "Manual build for SURFnet signers"

DEB_BUILD_OPTIONS="nocheck" dpkg-buildpackage -rfakeroot

cd ..

mv *.deb $HERE

cd /tmp

rm -rf ldnspkg-$$
