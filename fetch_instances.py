from reqto import get
from hashlib import sha256
import sqlite3
import sys
import json

with open("config.json") as f:
    config = json.loads(f.read())

domain = sys.argv[1]

blacklist = [
    "activitypub-troll.cf",
    "gab.best",
    "4chan.icu",
    "social.shrimpcam.pw",
    "mastotroll.netz.org",
    "github.dev",
    "ngrok.io"
]

headers = {
    "user-agent": config["useragent"]
}


def get_hash(domain: str) -> str:
    return sha256(domain.encode("utf-8")).hexdigest()


def get_peers(domain: str) -> str:
    try:
        res = get(f"https://{domain}/api/v1/instance/peers", headers=headers, timeout=5, allow_redirects=False)
        return res.json()
    except:
        return None

peerlist = get_peers(domain)

def get_type(instdomain: str) -> str:
    try:
        res = get(f"https://{instdomain}/nodeinfo/2.1.json", headers=headers, timeout=5, allow_redirects=False)
        if res.status_code == 404:
            res = get(f"https://{instdomain}/nodeinfo/2.0", headers=headers, timeout=5, allow_redirects=False)
        if res.status_code == 404:
            res = get(f"https://{instdomain}/nodeinfo/2.0.json", headers=headers, timeout=5, allow_redirects=False)
        if res.ok and "text/html" in res.headers["content-type"]:
            res = get(f"https://{instdomain}/nodeinfo/2.1", headers=headers, timeout=5, allow_redirects=False)
        if res.ok:
            if res.json()["software"]["name"] in ["akkoma", "rebased"]:
                return "pleroma"
            elif res.json()["software"]["name"] in ["hometown", "ecko"]:
                return "mastodon"
            elif res.json()["software"]["name"] in ["calckey", "groundpolis", "foundkey", "cherrypick", "firefish", "iceshrimp"]:
                return "misskey"
            else:
                return res.json()["software"]["name"]
        elif res.status_code == 404:
            res = get(f"https://{instdomain}/api/v1/instance", headers=headers, timeout=5, allow_redirects=False)
        if res.ok:
            return "mastodon"
    except:
        return None


conn = sqlite3.connect("blocks.db")
c = conn.cursor()

c.execute(
    "select domain from instances where 1"
)

for instance in peerlist:
    instance = instance.lower()

    if instance in blacklist:
        continue

    #print(instance) print while iterating over a list with thousands of members are stupid as they are
    #using up 60% of the cpu they are good for debuggin but after that they are just the very definition of bloat
    #If you do want to print that use a logger as they are usully programmed to minimize the time needed
    try:
        c.execute(
            "select domain from instances where domain = ?", (instance,)
        )
        if c.fetchone() == None:
            c.execute(
                "insert into instances select ?, ?, ?",
                (instance, get_hash(instance), get_type(instance)),
            )
        conn.commit()
    except Exception as e:
        print("error:", e, instance)
conn.close()
print("Done " + domain)
