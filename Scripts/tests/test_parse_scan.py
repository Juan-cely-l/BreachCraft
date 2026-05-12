from parse_scan import enrich_ssh_keys, extract_ssh_key_type, parse_nmap_xml


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="gateway.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.54"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_extracts_open_ports_and_versions() -> None:
    hosts = parse_nmap_xml(NMAP_XML)

    assert hosts == [
        {
            "ip": "192.168.1.10",
            "hostname": "gateway.local",
            "open_ports": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.9"},
                {"port": 80, "service": "http", "version": "Apache httpd 2.4.54"},
            ],
        },
    ]


def test_extract_ssh_key_type_ignores_comments() -> None:
    output = "# comment\n192.168.1.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n"

    assert extract_ssh_key_type(output) == "ssh-ed25519"


def test_enrich_ssh_keys_uses_injected_keyscan() -> None:
    hosts = parse_nmap_xml(NMAP_XML)

    enriched = enrich_ssh_keys(hosts, 1.0, keyscan=lambda _ip, _timeout: "ssh-rsa")

    assert enriched[0]["ssh_host_key_type"] == "ssh-rsa"
