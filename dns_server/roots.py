"""
Root hints — the bootstrap addresses of the 13 DNS root servers.

Recursion has a chicken-and-egg problem: to look up *anything* you must first
ask a root server, but to find a root server's address you'd need to... look it
up. The escape hatch is that these addresses are effectively constant (they
change maybe once a decade) and every resolver ships them baked in. This exact
list is published at https://www.internic.net/domain/named.root.

The names a.root-servers.net … m.root-servers.net are anycast: the single IP
below is announced from hundreds of physical locations worldwide, so "asking
198.41.0.4" really means "asking whichever a-root instance is nearest you."
"""

# (name, IPv4). We use IPv4 for simplicity; each also has an IPv6 (AAAA) address.
ROOT_SERVERS: list[tuple[str, str]] = [
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "199.9.14.201"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33"),
]

ROOT_HINT_IPS: list[str] = [ip for _, ip in ROOT_SERVERS]
