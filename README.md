# Dynamic DNS Solution for private networks.

Just like nip.io or xip.io, dynamicdns is a magic domain name that provides
wildcard DNS for any Private IP address.

| IP Address Range | Network Type | Description |
| ----- | ----- | ----- |
| 10.0.0.0/8	 | Private | Large-scale private networks |
| 172.16.0.0/12	 | Private | Medium-scale private networks |
| 192.168.0.0/16 | Private | Small-scale private networks |
| 100.64.0.0/10	 | CGNAT   | (Carrier-Grade NAT) Addresses used by Internet Service Providers (NAT44) |

Stop editing your etc/hosts file with custom hostname and IP address mappings.

ns53.me, ns10.me, ns172.me, ns192.me allows you to do that by mapping any IP Address to a hostname using the following formats:

## default octets:

```shell
default_octets = {
    "10": ("10", "100"),
    "100": ("64", "100"),
    "127": ("0", "100"),
    "172": ("16", "100"),
    "192": ("168", "100")
}
```

## Examples
- home.ns53.me maps to 127.0.0.1 
- local.ns53.me maps to 127.0.0.1 

## with use default octets

- apps.firm8.ns53.me maps to 100.64.8.100
- apps.customer8.ns10.me maps to 10.10.8.100
- apps.region8.ns172.me  maps to 172.16.8.100
- apps.vlan8.ns192.me  maps to 192.168.8.100


## other usage

- app101.customer1.vlan11.ns10.me maps to 10.11.1.101
- app102.customer2.vlan12.ns10.me maps to 10.12.2.102
- app103.customer3.vlan13.ns10.me maps to 10.13.3.103


## About this service

dynamicdns is powered by PowerDNS with a simple, custom PipeBackend written in Python: backend.py 

It's open source, licensed under Apache 2.0: https://github.com/zone9cloud/dynamicdns — pull requests are welcome. 

This is a free service provided by zone9.cloud. 

Feedback is appreciated, just raise an issue in [GitHub](https://github.com/zone9cloud/dynamicdns/issues).


# Troubleshooting

**DNS Rebinding Protection**

Some DNS resolvers, forwarders and routers have DNS rebinding protection which may result in failure to resolve local and private IP addresses. This service won't work in those situations. 


## Related Services

- nip.io: Dead simple wildcard DNS for any IP Address.
- localtls: A DNS server in Python3 to provide TLS to webservices on local addresses. It resolves addresses such as '192-168-0-1.yourdomain.net' to 192.168.0.1 and has a valid TLS certificate for them.
- sslip.io: Alternative to this service, supports IPv6 and custom domains.
- local.gd: Alternative to this service, where everything is mapped to localhost/127.0.0.1.
