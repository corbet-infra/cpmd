#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-or-later
# End-to-end test of the sops lookup and the sops_accounts inventory plugin with a throw-away age key and
# fake accounts (localhost). Needs ansible, sops and age on PATH. Nothing real is read or written.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
w=$(mktemp -d /dev/shm/crfs-test.XXXXXX)
trap 'for f in "$w"/*.yml "$w"/key.txt "$w"/sops.yaml; do [ -f "$f" ] && shred -u "$f"; done; find "$w" -mindepth 1 -delete; rmdir "$w"' EXIT
mkdir -p "$w/ac/ansible_collections/corbet" "$w/inv"
ln -s "$here" "$w/ac/ansible_collections/corbet/crfs"
age-keygen -o "$w/key.txt" 2>/dev/null
pub=$(age-keygen -y "$w/key.txt")
printf "creation_rules:\n  - age: %s\n" "$pub" > "$w/sops.yaml"
export SOPS_AGE_KEY_FILE="$w/key.txt" ANSIBLE_COLLECTIONS_PATH="$w/ac" ANSIBLE_CONFIG="$w/ansible.cfg"
cat > "$w/plain.yml" <<'Y'
accounts:
  - {host: localhost, ssh_user: demo, ssh_password: pw-one-xyzzy, service_id: "#9/#7"}
  - {host: localhost, ssh_user: demo, ssh_password: pw-two-xyzzy, service_id: "#9/#3"}
Y
sops --config "$w/sops.yaml" --encrypt --input-type yaml --output-type yaml "$w/plain.yml" > "$w/accounts.yml"
printf 'host: localhost\nssh_user: solo\nssh_password: pw-solo-xyzzy\n' > "$w/plain2.yml"
sops --config "$w/sops.yaml" --encrypt --input-type yaml --output-type yaml "$w/plain2.yml" > "$w/solo.yml"
printf 'admin_ssh_key: |\n  -----BEGIN FAKE-----\n  abc\n  -----END FAKE-----\n' > "$w/plain3.yml"
sops --config "$w/sops.yaml" --encrypt --input-type yaml --output-type yaml "$w/plain3.yml" > "$w/admin.yml"
shred -u "$w/plain.yml" "$w/plain2.yml" "$w/plain3.yml"
touch "$w/known_hosts"
printf '[defaults]\nenable_plugins = host_list, yaml, ini, corbet.crfs.sops_accounts\n[inventory]\nenable_plugins = host_list, yaml, ini, corbet.crfs.sops_accounts\n' > "$w/ansible.cfg"
cat > "$w/inv/t.sops_accounts.yml" <<Y
plugin: corbet.crfs.sops_accounts
known_hosts: ../known_hosts
sources:
  - {file: $w/accounts.yml, list_key: accounts, name_format: 'cld-{i}', sort_by: service_id, sort_regex: '#(\\d+)\$', group: cluster}
  - {file: $w/solo.yml, name: playground, group: testbox}
admin_key: {file: $w/admin.yml, key: admin_ssh_key}
Y
out=$(ansible-inventory -i "$w/inv/t.sops_accounts.yml" --list)
echo "$out" | grep -q '"cld-1"' || { echo "FAIL cld-1 missing"; exit 1; }
echo "$out" | grep -q '"playground"' || { echo "FAIL playground missing"; exit 1; }
echo "$out" | grep -q 'xyzzy' && { echo "FAIL a password is in the inventory output"; exit 1; }
echo "$out" | grep -q "lookup('corbet.crfs.sops'" || { echo "FAIL password template missing"; exit 1; }
echo "$out" | grep -q '"service_id"' || { echo "FAIL attrs missing"; exit 1; }
# the lookup resolves the template (length only, never the value)
n=$(ansible -i "$w/inv/t.sops_accounts.yml" cld-1 -m ansible.builtin.debug -a 'msg={{ ansible_password | length }}' -c local 2>&1 | grep -o '"msg": [0-9]*' | grep -o '[0-9]*$')
[ "$n" = 12 ] || { echo "FAIL password length via lookup was '$n'"; exit 1; }
# key mode writes a 0600 /dev/shm file and shreds it at exit
out=$(CRFS_AUTH=key ansible-inventory -i "$w/inv/t.sops_accounts.yml" --list)
echo "$out" | grep -q '"crfs_admin_key_file"' || { echo "FAIL key mode"; exit 1; }
ls /dev/shm 2>/dev/null | grep -q '^crfs-admin-key' && { echo "FAIL key file left behind"; exit 1; }
echo "inventory OK"
# numbering follows the sort key: cld-0 is the account with the smallest id (#3 = second list entry)
h0=$(ansible-inventory -i "$w/inv/t.sops_accounts.yml" --host cld-0)
echo "$h0" | grep -q '#9/#3' || { echo "FAIL cld-0 is not the lowest id: $h0"; exit 1; }
echo "sorting OK"
