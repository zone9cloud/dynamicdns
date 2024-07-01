# Dynamic DNS Solution for private networks.

Just like nip.io or xip.io, dynamicdns is a magic domain name that provides
wildcard DNS for any Private IP address.

Stop editing your etc/hosts file with custom hostname and IP address mappings.

ns10.me, ns172.me, ns192.me allows you to do that by mapping any IP Address to a hostname using the following formats:

## default octets:

```shell
default_octets = {
    "10": ("10", "100"),
    "127": ("0", "100"),
    "172": ("16", "100"),
    "192": ("168", "100")
}
```

## with use default octets
- my.ns53.me maps to 127.0.0.1 

## with use default octets

- apps.firm8.ns10.me maps to 10.10.8.100
- apps.firm8.ns172.me  maps to 172.16.8.100
- apps.firm8.ns192.me  maps to 192.168.8.100


## other usage

- app101.customer1.vlan11.ns10.me maps to 10.11.1.101
- app102.customer2.vlan12.ns10.me maps to 10.12.2.102
- app103.customer3.vlan13.ns10.me maps to 10.13.3.103


## About this service

dynamicdns is powered by PowerDNS with a simple, custom PipeBackend written in Python: backend.py 

It's open source, licensed under Apache 2.0: https://github.com/zone9cloud/dynamicdns — pull requests are welcome. 

This is a free service provided by zone9.cloud. 

Feedback is appreciated, just raise an issue in [GitHub](https://github.com/zone9cloud/dynamicdns/issues).


| IP Adres Aralığı |	Ağ Türü |	Açıklama |
| ----- | ----- | ----- |
| 10.0.0.0/8	   | Özel (Private)	| Büyük ölçekli özel ağlar |
| 172.16.0.0/12	 | Özel (Private)	| Orta ölçekli özel ağlar |
| 192.168.0.0/16 | Özel (Private)	| Küçük ölçekli özel ağlar |
| 100.64.0.0/10	 | CGNAT	        | [(Carrier-Grade NAT)](https://en.wikipedia.org/wiki/Carrier-grade_NAT)	İnternet servis sağlayıcıları tarafından kullanılan adresler (NAT44) |


# Troubleshooting

**DNS Rebinding Protection**

Some DNS resolvers, forwarders and routers have DNS rebinding protection which may result in failure to resolve local and private IP addresses. This service won't work in those situations. 


## Related Services

- nip.io: Dead simple wildcard DNS for any IP Address.
- localtls: A DNS server in Python3 to provide TLS to webservices on local addresses. It resolves addresses such as '192-168-0-1.yourdomain.net' to 192.168.0.1 and has a valid TLS certificate for them.
- sslip.io: Alternative to this service, supports IPv6 and custom domains.
- local.gd: Alternative to this service, where everything is mapped to localhost/127.0.0.1.
