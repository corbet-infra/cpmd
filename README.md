<!-- SPDX-License-Identifier: LGPL-3.0-or-later -->
# corbet.cpmd - box basics for rented Pulsed Media seedboxes

An Ansible collection for rented seedbox accounts (Pulsed Media "Storage Box" class: shared Debian VMs, **no root**, one
unprivileged user). It holds what every service on such an account needs, whatever it stores: the inventory, a fact
sheet of the box, the removal of the shop image's leftovers, account hardening and a TLS leaf. Nothing runs as root,
nothing needs `become`, nothing is installed outside the account's home directory.

The services that run on top live in sibling collections: [crfs](https://git.corbet.ch/corbet-infra/crfs) (RustFS) and
[cswd](https://git.corbet.ch/corbet-infra/cswd) (SeaweedFS). Both depend on this one.

| Role | What it does |
|---|---|
| `agent` | Installs a tiny stdlib-Python helper under `~/cold/bin` (facts, quota, a minimal SigV4 client) and the private `~/cold` tree |
| `facts` | Runs the agent and writes a JSON fact sheet per account (limits, cgroup, quota, ports, memory) |
| `debloat` | Switches off the shop image's media stack, torrent clients and rootless Docker; stops leftovers by exact PID; reports what the provider restarts |
| `harden` | Account modes, ONE restricted SSH key (no forwarding; `from=` only if you give a source list), `umask 077`, "other" bits removed from our trees, listener audit, security fact sheet |
| `tls` | Leaf certificate per box from your own CA; the key is made on the box and never leaves it, the CA key goes from sops straight into openssl |

Plugins: `corbet.cpmd.sops_accounts` (inventory from sops files; passwords are never in inventory output) and
`corbet.cpmd.sops` (lookup of ONE sops value). Playbooks: `facts`, `bootstrap` (facts, debloat, harden) and `sshkey`
(rewrite only the admin key line and prove a fresh key login).

## Suitable for

Any rootless service on a rented account that has an SSH password and an assigned port range. Not suitable for hosts
where you have root (use a normal configuration tool) or for non-Debian images (the agent assumes Debian 12 userland,
python3.11, `systemd --user`, `ss`, x86_64).

## How to use

1. Create sops files (see `examples/accounts.sample.yml`): the account list (host, ssh_user, ssh_password) and later the
   admin SSH key (`admin_ssh_key`).
2. Copy `examples/` next to your playbooks and edit the paths (documentation addresses are used there), then
   `ansible-galaxy collection install git+https://git.corbet.ch/corbet-infra/cpmd.git`.
3. Pin host keys: `tools/scan-hostkeys known_hosts` (first contact is trust-on-first-use; verify from a second vantage point).
4. **Try everything on one account first**, then one production account, then the rest:

```sh
ansible-playbook corbet.cpmd.facts     -e target=playground
ansible-playbook corbet.cpmd.bootstrap -e target=playground --check --diff
ansible-playbook corbet.cpmd.bootstrap -e target=playground
CPMD_AUTH=key ansible -m ping playground          # after the admin key is installed by `harden`
```

The inventory plugin sets `cpmd_label` (the provider's host label), `cpmd_index`, `cpmd_attrs` (any other plain fields of
the entry) and, in key mode, `cpmd_admin_key_file` (a 0600 file in `/dev/shm`, shredded at exit).

The `tls` role is used by other roles through `include_role`; set `tls_names`, `tls_ips`, `tls_ca_cert_file` and
`tls_ca_key_sops_file` (see `roles/tls/defaults/main.yml`). It leaves `key.pem`, `cert.pem` and `ca.pem` in `tls_dir`
and sets the fact `tls_changed` when it wrote any of them.

## Limits and known issues

* `harden_ssh_from` is optional: an empty list means no `from=` (use that when your egress address is not yours to control;
  a `from=` list that misses the controller locks the key out and leaves the password login as the way back).
* `debloat` cannot switch off what the provider restarts as root (Docker is the example); it stops the processes and tells you.
* The box-side names (`~/cold`, `crfs-agent`, the `crfs hardening` block marker, the `CRFS_PORTS` and `CRFS_UNITS` variables
  of the agent) keep the names of the first collection they shipped in, so that boxes already set up are not touched twice.
* Changing the namespace of the three collections: `tools/set-namespace <new>`.

## Tests

* `tests/fixture/test-own-procs.sh` - the PID-exact process stopper.
* `tests/fixture/test-inventory.sh` - lookup and inventory plugin end to end with a throw-away age key (needs ansible, sops, age).
* `tools/leak-scan.sh [patterns]` - run before every push of this public repository.

## License

LGPL-3.0-or-later (`LICENSE`, plus the GPL-3.0 it refers to in `COPYING`).
