#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-or-later
# Prints OK when the leaf of this box is good, otherwise the reason (one word). Arguments: expected SAN list,
# fingerprint of the CA, optionally the directory of the leaf (default ~/cold/tls). Read-only.
d=${3:-"$HOME/cold/tls"}
want_san=$1; ca_fp=$2
[ -f "$d/key.pem" ] || { echo NOKEY; exit 0; }
[ -f "$d/cert.pem" ] || { echo NOCERT; exit 0; }
[ -f "$d/ca.pem" ] || { echo NOCA; exit 0; }
fp=$(openssl x509 -in "$d/ca.pem" -noout -fingerprint -sha256 | cut -d= -f2)
[ "$fp" = "$ca_fp" ] || { echo CAOLD; exit 0; }
openssl verify -CAfile "$d/ca.pem" "$d/cert.pem" >/dev/null 2>&1 || { echo NOVERIFY; exit 0; }
openssl x509 -in "$d/cert.pem" -noout -checkend 2592000 >/dev/null || { echo EXPIRING; exit 0; }
got=$(openssl x509 -in "$d/cert.pem" -noout -ext subjectAltName | tail -1 | tr -d ' ')
exp=$(echo "$want_san" | sed 's/IP:/IPAddress:/g' | tr -d ' ')
gotn=$(echo "$got" | tr ',' '\n' | sort | tr '\n' ',')
expn=$(echo "$exp" | tr ',' '\n' | sort | tr '\n' ',')
[ "$gotn" = "$expn" ] || { echo SANDIFF; exit 0; }
pk=$(openssl pkey -in "$d/key.pem" -pubout 2>/dev/null | sha256sum | cut -d' ' -f1)
ck=$(openssl x509 -in "$d/cert.pem" -noout -pubkey | sha256sum | cut -d' ' -f1)
[ "$pk" = "$ck" ] || { echo KEYMISMATCH; exit 0; }
echo OK
