# python phpIPAM network scanner

Multithreaded network scanner to update status tag using the phpIPAM HTTPS API

Tries to scans hosts with ping, then falls back to minimal port scan for hosts that block ICMP.
Does reverse lookup of IP to populate hostname

IPv4 and IPv6 compatible
