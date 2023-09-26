from hashlib import sha256
from multiprocessing import Lock, cpu_count, set_start_method, Process #Pool,
from httpx import AsyncClient
import aiohttp
import asyncio
import sqlite3
import sys
import json

async def get_hash(domain: str) -> str:
    return sha256(domain.encode("utf-8")).hexdigest()

async def get_peers(domain: str) -> str:
    try:
        async with aiohttp.ClientSession() as session:
            res  = await session.get(f"https://{domain}/api/v1/instance/peers") #, headers=headers, timeout=5, allow_redirects=False)
            resj = await res.json()
            return resj
    except Exception as e:
        print(e)
        return None

async def get_type(instdomain: str) -> str:
    try:
        async with aiohttp.ClientSession() as session:
            res = await session.get(f"https://{instdomain}/nodeinfo/2.1.json", headers=headers, timeout=5, allow_redirects=False)
            if res.status == 404:
                res  = await session.get(f"https://{instdomain}/nodeinfo/2.0", headers=headers, timeout=5, allow_redirects=False)
            if res.status == 404:
                res  = await session.get(f"https://{instdomain}/nodeinfo/2.0.json", headers=headers, timeout=5, allow_redirects=False)
            if res.ok and "text/html" in res.headers["content-type"]:
                res = await session.get(f"https://{instdomain}/nodeinfo/2.1", headers=headers, timeout=5, allow_redirects=False)
            if res.ok:
                try:
                    resj = await res.json()
                except aiohttp.ContentTypeError:
                    data = await res.read()
                    resj = json.loads(data)
                if resj["software"]["name"] in ["akkoma", "rebased"]:
                    return "pleroma"
                elif resj["software"]["name"] in ["hometown", "ecko"]:
                    return "mastodon"
                elif resj["software"]["name"] in ["calckey", "groundpolis", "foundkey", "cherrypick", "firefish", "iceshrimp"]:
                    return "misskey"
                else:
                    return resj["software"]["name"]
            elif res.status == 404:
                res = await session.get(f"https://{instdomain}/api/v1/instance", headers=headers, timeout=5, allow_redirects=False)
            if res.ok:
                return "mastodon"
    except Exception as e:
        return None

async def write_instance(instance: str, c) -> bool:
    try:
        c.execute(
            "select domain from instances where domain = ?", (instance,)
        )
        if c.fetchone() == None:
            InstHash = await get_hash(instance)
            InstType = await get_type(instance)
            c.execute(
                "insert into instances select ?, ?, ?",
                (instance, InstHash, InstType),
            )
            conn.commit()
    except Exception as e:
        print("error:", e, instance)
    return True

async def main():
    global config
    global headers
    global domain
    global conn
    with open("config.json") as f:
        config = json.loads(f.read())
    headers    = {"user-agent": config["useragent"]}
    domain     = sys.argv[1]
    conn = sqlite3.connect("blocks.db")
    c = conn.cursor()
    peerlist =  await get_peers(domain)
    blacklist = [ "activitypub-troll.cf","gab.best","4chan.icu","social.shrimpcam.pw","mastotroll.netz.org","github.dev", "ngrok.io"]
    async with asyncio.TaskGroup() as tg:
        for peer in peerlist: #[:1000]:
            peer = peer.lower()
            blacklisted = False
            for ddomain in blacklist:
                if ddomain in peer:
                    blacklisted = True
            if blacklisted:
                continue

            tg.create_task(write_instance(peer, c))
    conn.close()
    print(f"done with {domain}")

if __name__ == "__main__":
    asyncio.run(main())

sys.exit()
