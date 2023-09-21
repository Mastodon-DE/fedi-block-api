from reqto import get
from hashlib import sha256
from multiprocessing import Pool, Lock, cpu_count
import sqlite3
import sys
import json

mutex = Lock()

def get_hash(domain: str) -> str:
    return sha256(domain.encode("utf-8")).hexdigest()


def get_peers(domain: str) -> str:
    try:
        res = get(f"https://{domain}/api/v1/instance/peers", headers=headers, timeout=5, allow_redirects=False)
        return res.json()
    except:
        return None


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

def write_instance(instance: str, c) -> None:
    print("run")
    try:
        with mutex:
            c.execute(
                "select domain from instances where domain = ?", (instance,)
            )
        if c.fetchone() == None:
            InstType = get_type(instance)
            InstHash = get_hash(instance)
            with mutex:
                c.execute(
                    "insert into instances select ?, ?, ?",
                    (instance, InstHash, InstType),
                )
            with mutex:
                conn.commit()
    except Exception as e:
        print("error:", e, instance)

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

peerlist = get_peers(domain)

conn = sqlite3.connect("blocks.db")

c = conn.cursor()

c.execute(
    "select domain from instances where 1"
)

pool = Pool(cpu_count() - 1)

#This one will create a pool of processes
#With the same number as cpus on the host
#But minus 1 for the os
#This should hopefully fix accidentally
#creating forkbombs and crashing the kernel
#(it was fun though)

for instance in peerlist:
    instance = instance.lower()

    blacklisted = False
    for ddomain in blacklist:
        if ddomain in instance:
            blacklisted = True

    if blacklisted:
        continue

    #p = Process(target=write_instance, args=[instance, c])
    #p.start()
    #Funny story about that
    #Thats a fork bomb do not run that
    #Except for lolz thats why I didnt delete it

    #write_instance(instance, c)
    #DEBUG PLEASE REMOVE AFTER USE
    #print(instance) #REMOVE AFTER USE OR PERFOMANCE IS GONNA TANK
    #DEBUG PLEASE REMOVE AFTER USE

conn.close()
print("done " + domain)
