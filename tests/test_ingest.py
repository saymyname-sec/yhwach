

def test_bloodhound_memberof_becomes_a_membership(tmp_db) -> None:
    """`membership` had no writer at all: SharpHound carries a group's roster in
    `Members`, the parser ignored it, and the ingest never wrote a membership —
    so group nesting was invisible and an empty Groups panel read as "this domain
    is flat"."""
    import json

    from yhwach import db as _db
    from yhwach.ingest import ingest_bloodhound_graph

    graph = json.dumps({
        "meta": {"type": "groups"},
        "data": [{
            "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL"},
            "Members": [
                {"ObjectIdentifier": "J.VARGA@CORP.LOCAL", "ObjectType": "User"},
                {"ObjectIdentifier": "TIER0 ADMINS@CORP.LOCAL", "ObjectType": "Group"},
            ],
        }],
    })
    with _db.transaction(tmp_db) as conn:
        eid = _db.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        summary = ingest_bloodhound_graph(conn, eid, graph)
        rows = conn.execute(
            "SELECT p.name member, q.name grp FROM membership m "
            "JOIN principal p ON p.id=m.member_id JOIN principal q ON q.id=m.group_id "
            "WHERE m.engagement_id=? ORDER BY p.name", (eid,)).fetchall()
    assert summary["memberships"] == 2, summary
    pairs = {(r["member"].lower(), r["grp"].lower()) for r in rows}
    assert ("j.varga", "domain admins") in pairs
    assert ("tier0 admins", "domain admins") in pairs


def test_bloodhound_group_with_no_members_is_fine(tmp_db) -> None:
    import json

    from yhwach import db as _db
    from yhwach.ingest import ingest_bloodhound_graph

    graph = json.dumps({"meta": {"type": "groups"},
                        "data": [{"Properties": {"name": "EMPTY@CORP.LOCAL"}}]})
    with _db.transaction(tmp_db) as conn:
        eid = _db.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        summary = ingest_bloodhound_graph(conn, eid, graph)
    assert summary["memberships"] == 0
    assert summary["principals"] == 1


def test_ingest_web_records_params_and_auth_gating(tmp_db) -> None:
    """`web_path.params` is documented as "the injection surface" and was
    structurally unwritable: ParsedWebPath had no such field, so nothing could
    pass one. `auth_required` was always 0 and `server`/`tech` always NULL,
    because both callers invoked ingest_web positionally."""
    from yhwach import db as _db
    from yhwach.ingest import ingest_web

    gobuster = (
        "/api/query?q=test&collection=wiki (Status: 200) [Size: 2210]\n"
        "/admin                            (Status: 403) [Size: 162]\n"
        "/login                            (Status: 200) [Size: 3310]\n"
    )
    with _db.transaction(tmp_db) as conn:
        eid = _db.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        hid = conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                           "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,)).lastrowid
        summ = ingest_web(conn, int(hid), "http://10.0.0.5", gobuster,
                          server="nginx/1.24.0", tech="nginx,FastAPI",
                          title="Wiki Assistant", vhost="wiki.corp")
        app = conn.execute("SELECT * FROM web_app WHERE host_id=?", (int(hid),)).fetchone()
        paths = {r["path"]: r for r in conn.execute(
            "SELECT * FROM web_path WHERE web_app_id=?", (app["id"],))}

    assert app["server"] == "nginx/1.24.0" and app["tech"] == "nginx,FastAPI"
    assert app["title"] == "Wiki Assistant" and app["vhost"] == "wiki.corp"

    q = next(r for p, r in paths.items() if p.startswith("/api/query"))
    assert q["params"] == "q,collection", q["params"]
    assert not q["auth_required"]
    assert paths["/admin"]["auth_required"] == 1
    assert paths["/login"]["params"] is None

    assert summ["with_params"] == 1 and summ["auth_gated"] == 1


def test_parsed_web_path_params_dedupe_and_empty() -> None:
    from yhwach.parsers.web import ParsedWebPath

    assert ParsedWebPath("/x").params is None
    assert ParsedWebPath("/x?").params is None
    assert ParsedWebPath("/x?a=1&a=2&b=3").params == "a,b"
    assert ParsedWebPath("/x", status=401).auth_required
    assert ParsedWebPath("/x", status=403).auth_required
    assert not ParsedWebPath("/x", status=200).auth_required


def test_nmap_records_tls_cert_names_as_vhosts(tmp_db) -> None:
    """`db.add_domain` had no caller anywhere, so vhosts and subdomains were never
    recorded — while -sC is in every scanner template, meaning the certificate
    SANs were already in the XML on disk and discarded at parse time."""
    from yhwach import db as _db
    from yhwach.parsers.nmap import insert_hosts, parse_nmap

    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="10.0.0.5" addrtype="ipv4"/>
        <hostnames>
          <hostname name="web01.corp.local"/>
          <hostname name="www.corp.local"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="443"><state state="open"/>
            <service name="https" product="nginx"/>
            <script id="ssl-cert" output="Subject: commonName=portal.corp.local
Subject Alternative Name: DNS:portal.corp.local, DNS:*.staging.corp.local"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    hosts = parse_nmap(xml)
    assert hosts[0].hostname == "web01.corp.local"
    assert "portal.corp.local" in hosts[0].names
    assert "staging.corp.local" in hosts[0].names, "a wildcard SAN was not normalised"

    with _db.transaction(tmp_db) as conn:
        eid = _db.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        insert_hosts(conn, eid, hosts)
        names = {r["name"] for r in conn.execute(
            "SELECT name FROM domain WHERE engagement_id=?", (eid,))}
    assert "portal.corp.local" in names
    assert "staging.corp.local" in names
    assert "www.corp.local" in names          # the second PTR alias
    assert "web01.corp.local" not in names    # the primary is host.hostname


def test_nmap_without_certs_records_no_domains(tmp_db) -> None:
    from yhwach import db as _db
    from yhwach.parsers.nmap import insert_hosts, parse_nmap

    xml = ('<?xml version="1.0"?><nmaprun><host>'
           '<address addr="10.0.0.6" addrtype="ipv4"/>'
           '<ports><port protocol="tcp" portid="22"><state state="open"/>'
           '<service name="ssh"/></port></ports></host></nmaprun>')
    with _db.transaction(tmp_db) as conn:
        eid = _db.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        insert_hosts(conn, eid, parse_nmap(xml))
        n = conn.execute("SELECT COUNT(*) c FROM domain").fetchone()["c"]
    assert n == 0
