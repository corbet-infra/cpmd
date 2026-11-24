# ygg_proxy

A rootless Yggdrasil-ng proxy (userspace stack, no TUN, no root, no become) as a systemd user unit of a box account, with local TCP forwards
into the mesh. The role copies two static binaries from the controller (`ygg_proxy_src`, the `bin/` of a static build of `yggdrasil` and
`yggdrasil-proxy`), renders the closed-mesh configuration (peers with pinned keys, allowed keys, no multicast) and runs the unit. The node key is
generated on the box at the first start and never leaves it; its public side is `<ygg_proxy_base_dir>/etc/public` for the harvest.

Variables: see `defaults/main.yml`. The unit sets no memory or CPU limit on purpose.
