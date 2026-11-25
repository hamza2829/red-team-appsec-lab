"""F03 Stored XSS: a ticket body with a script tag is rendered unescaped.

Expected (vuln): the raw <script> appears in the HTML of GET /tickets/{id}.
Expected (fixed): the payload is HTML-escaped.
"""

from lab import auth_header, banner, client, login

PAYLOAD = "<script>document.title='pwned'</script>"


def run():
    banner("Stored XSS on GET /tickets/{id}")
    c = client()
    tok = login(c, "alice", "alice-pw")["token"]
    tid = c.post(
        "/api/tickets", headers=auth_header(tok), json={"title": "x", "body": PAYLOAD}
    ).json()["id"]
    html = c.get(f"/tickets/{tid}").text
    print(f"rendered body contains raw script: {PAYLOAD in html}")
    return PAYLOAD in html


if __name__ == "__main__":
    print("VULNERABLE" if run() else "not exploitable (fixed)")
