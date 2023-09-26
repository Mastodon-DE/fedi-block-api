from reqto import get
from reqto import post
from hashlib import sha256
import sqlite3
from bs4 import BeautifulSoup
from json import dumps
from json import loads
import re
from time import time
import itertools

with open("config.json") as f:
    config = loads(f.read())

headers = {
    "user-agent": config["useragent"]
}

def send_bot_post(instance: str, blocks: dict):
    message = instance + " has blocked the following instances:\n\n"
    truncated = False
    if len(blocks) > 20:
        truncated = True
        blocks = blocks[0 : 19]
    for block in blocks:
        if block["reason"] == None or block["reason"] == '':
            message = message + block["blocked"] + " with unspecified reason\n"
        else:
            if len(block["reason"]) > 420:
                block["reason"] = block["reason"][0:419] + "[…]"
            message = message + block["blocked"] + ' for "' + block["reason"].replace("@", "@\u200b") + '"\n'
    if truncated:
        message = message + "(the list has been truncated to the first 20 entries)"

    botheaders = {**headers, **{"Authorization": "Bearer " + config["bot_token"]}}
    req = post(f"{config['bot_instance']}/api/v1/statuses",
        data={"status":message, "visibility":config['bot_visibility'], "content_type":"text/plain"},
        headers=botheaders, timeout=10).json()
    return True

def get_mastodon_blocks(domain: str) -> dict:
    blocks = {
        "Suspended servers": [],
        "Filtered media": [],
        "Limited servers": [],
        "Silenced servers": [],
    }

    translations = {
        "Silenced instances": "Silenced servers",
        "Suspended instances": "Suspended servers",
        "Gesperrte Server": "Suspended servers",
        "Gefilterte Medien": "Filtered media",
        "Stummgeschaltete Server": "Silenced servers",
        "停止済みのサーバー": "Suspended servers",
        "メディアを拒否しているサーバー": "Filtered media",
        "サイレンス済みのサーバー": "Silenced servers",
        "שרתים מושעים": "Suspended servers",
        "מדיה מסוננת": "Filtered media",
        "שרתים מוגבלים": "Silenced servers",
        "Serveurs suspendus": "Suspended servers",
        "Médias filtrés": "Filtered media",
        "Serveurs limités": "Silenced servers",
    }

    try:
        doc = BeautifulSoup(
            get(f"https://{domain}/about/more", headers=headers, timeout=5, allow_redirects=False).text,
            "html.parser",
        )
    except:
        return {}

    for header in doc.find_all("h3"):
        header_text = header.text
        if header_text in translations:
            header_text = translations[header_text]
        if header_text in blocks:
            # replaced find_next_siblings with find_all_next to account for instances that e.g. hide lists in dropdown menu
            for line in header.find_all_next("table")[0].find_all("tr")[1:]:
                blocks[header_text].append(
                    {
                        "domain": line.find("span").text,
                        "hash": line.find("span")["title"][9:],
                        "reason": line.find_all("td")[1].text.strip(),
                    }
                )
    return {
        "reject": blocks["Suspended servers"],
        "media_removal": blocks["Filtered media"],
        "followers_only": blocks["Limited servers"]
        + blocks["Silenced servers"],
    }

def get_friendica_blocks(domain: str) -> dict:
    blocks = []

    try:
        doc = BeautifulSoup(
            get(f"https://{domain}/friendica", headers=headers, timeout=5, allow_redirects=False).text,
            "html.parser",
        )
    except:
        return {}

    blocklist = doc.find(id="about_blocklist")
    for line in blocklist.find("table").find_all("tr")[1:]:
            blocks.append(
                {
                    "domain": line.find_all("td")[0].text.strip(),
                    "reason": line.find_all("td")[1].text.strip()
                }
            )

    return {
        "reject": blocks
    }

def get_pisskey_blocks(domain: str) -> dict:
    blocks = {
        "suspended": [],
        "blocked": []
    }

    try:
        counter = 0
        step = 99
        while True:
            # iterating through all "suspended" (follow-only in its terminology) instances page-by-page, since that troonware doesn't support sending them all at once
            try:
                if counter == 0:
                    doc = post(f"https://{domain}/api/federation/instances", data=dumps({"sort":"+caughtAt","host":None,"suspended":True,"limit":step}), headers=headers, timeout=5, allow_redirects=False).json()
                    if doc == []: raise
                else:
                    doc = post(f"https://{domain}/api/federation/instances", data=dumps({"sort":"+caughtAt","host":None,"suspended":True,"limit":step,"offset":counter-1}), headers=headers, timeout=5, allow_redirects=False).json()
                    if doc == []: raise
                for instance in doc:
                    # just in case
                    if instance["isSuspended"]:
                        blocks["suspended"].append(
                            {
                                "domain": instance["host"],
                                # no reason field, nothing
                                "reason": ""
                            }
                        )
                counter = counter + step
                # for now I'll assume no one in their right mind would block more than 2500 instances
                # greetings to abstroonztaube
                if counter > 2500:
                    break
            except:
                counter = 0
                break

        while True:
            # same shit, different asshole ("blocked" aka full suspend)
            try:
                if counter == 0:
                    doc = post(f"https://{domain}/api/federation/instances", data=dumps({"sort":"+caughtAt","host":None,"blocked":True,"limit":step}), headers=headers, timeout=5, allow_redirects=False).json()
                    if doc == []: raise
                else:
                    doc = post(f"https://{domain}/api/federation/instances", data=dumps({"sort":"+caughtAt","host":None,"blocked":True,"limit":step,"offset":counter-1}), headers=headers, timeout=5, allow_redirects=False).json()
                    if doc == []: raise
                for instance in doc:
                    if instance["isBlocked"]:
                        blocks["blocked"].append(
                            {
                                "domain": instance["host"],
                                "reason": ""
                            }
                        )
                counter = counter + step
                if counter > 2500:
                    break
            except:
                counter = 0
                break

        return {
            "reject": blocks["blocked"],
            "followers_only": blocks["suspended"]
        }

    except:
        return {}

def get_hash(domain: str) -> str:
    return sha256(domain.encode("utf-8")).hexdigest()


def get_type(domain: str) -> str:
    try:
        res = get(f"https://{domain}/nodeinfo/2.1.json", headers=headers, timeout=5, allow_redirects=False)
        if res.status_code == 404:
            res = get(f"https://{domain}/nodeinfo/2.0", headers=headers, timeout=5, allow_redirects=False)
        if res.status_code == 404:
            res = get(f"https://{domain}/nodeinfo/2.0.json", headers=headers, timeout=5, allow_redirects=False)
        if res.ok and "text/html" in res.headers["content-type"]:
            res = get(f"https://{domain}/nodeinfo/2.1", headers=headers, timeout=5, allow_redirects=False)
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
            res = get(f"https://{domain}/api/v1/instance", headers=headers, timeout=5, allow_redirects=False)
        if res.ok:
            return "mastodon"
    except:
        return None

def tidyup(domain: str) -> str:
    # some retards put their blocks in variable case
    domain = domain.lower()
    # other retards put the port
    domain = re.sub("\:\d+$", "", domain)
    # bigger retards put the schema in their blocklist, sometimes even without slashes
    domain = re.sub("^https?\:(\/*)", "", domain)
    # and trailing slash
    domain = re.sub("\/$", "", domain)
    # and the @
    domain = re.sub("^\@", "", domain)
    # the biggest retards of them all try to block individual users
    domain = re.sub("(.+)\@", "", domain)
    # some retards also started putting a single asterisk without dot for subdomain blocks
    if domain.count("*") <= 1 and domain.startswith("*"):
        domain = re.sub("^\*", "*.", domain)
        domain = re.sub("^\*\.\.", "*.", domain)
    # and a dot before the domain
    domain = re.sub("^\.", "", domain)
    # and whitespaces in the beginning/end
    domain = re.sub("^\ ", "", domain)
    domain = re.sub("\ $", "", domain)

    return domain

conn = sqlite3.connect("blocks.db")
c = conn.cursor()

c.execute(
    "select domain, software from instances where software in ('pleroma', 'mastodon', 'friendica', 'misskey', 'gotosocial', 'lemmy')"
)

for blocker, software in c.fetchall():
    blockdict = []
    blocker = tidyup(blocker)
    if software == "pleroma":
        try:
            # Blocks
            federation = get(
                f"https://{blocker}/nodeinfo/2.1.json", headers=headers, timeout=5, allow_redirects=False
            ).json()["metadata"]["federation"]
            if "mrf_simple" in federation:
                for block_level, blocks in (
                    {**federation["mrf_simple"],
                    **{"quarantined_instances": federation["quarantined_instances"]}}
                ).items():
                    for blocked in blocks:
                        blocked = tidyup(blocked)
                        if blocked == "":
                            continue
                        if blocked.count("*") > 1:
                            # -ACK!-oma also started obscuring domains without hash
                            c.execute(
                                "select domain from instances where domain like ? order by rowid limit 1", (blocked.replace("*", "_"),)
                            )
                            searchres = c.fetchone()
                            if searchres != None:
                                blocked = searchres[0]

                        c.execute(
                            "select domain from instances where domain = ?", (blocked,)
                        )
                        if c.fetchone() == None:
                            c.execute(
                                "insert into instances select ?, ?, ?",
                                (blocked, get_hash(blocked), get_type(blocked)),
                            )
                        timestamp = int(time())
                        c.execute(
                            "select * from blocks where blocker = ? and blocked = ? and block_level = ?",
                            (blocker, blocked, block_level),
                        )
                        if c.fetchone() == None:
                            c.execute(
                                "insert into blocks select ?, ?, '', ?, ?, ?",
                                (blocker, blocked, block_level, timestamp, timestamp),
                            )
                            if block_level == "reject":
                                blockdict.append(
                                    {
                                        "blocked": blocked,
                                        "reason": None
                                    })
                        else:
                            c.execute(
                                "update blocks set last_seen = ? where blocker = ? and blocked = ? and block_level = ?",
                                (timestamp, blocker, blocked, block_level)
                            )
            conn.commit()
            # Reasons
            if "mrf_simple_info" in federation:
                for block_level, info in (
                    {**federation["mrf_simple_info"],
                    **(federation["quarantined_instances_info"]
                    if "quarantined_instances_info" in federation
                    else {})}
                ).items():
                    for blocked, reason in info.items():
                        blocked = tidyup(blocked)
                        if blocked == "":
                            continue
                        if blocked.count("*") > 1:
                            # same domain guess as above, but for reasons field
                            c.execute(
                                "select domain from instances where domain like ? order by rowid limit 1", (blocked.replace("*", "_"),)
                            )
                            searchres = c.fetchone()
                            if searchres != None:
                                blocked = searchres[0]
                        c.execute(
                            "update blocks set reason = ? where blocker = ? and blocked = ? and block_level = ? and reason = ''",
                            (reason["reason"], blocker, blocked, block_level),
                        )
                        for entry in blockdict:
                            if entry["blocked"] == blocked:
                                entry["reason"] = reason["reason"]

            conn.commit()
        except Exception as e:
            print("error:", e, blocker)
    elif software == "mastodon":
        try:
            # json endpoint for newer mastodongs
            try:
                json = {
                    "reject": [],
                    "media_removal": [],
                    "followers_only": [],
                    "report_removal": []
                }

                # handling CSRF, I've saw at least one server requiring it to access the endpoint
                meta = BeautifulSoup(
                    get(f"https://{blocker}/about", headers=headers, timeout=5, allow_redirects=False).text,
                    "html.parser",
                )
                try:
                    csrf = meta.find("meta", attrs={"name": "csrf-token"})["content"]
                    reqheaders = {**headers, **{"x-csrf-token": csrf}}
                except:
                    reqheaders = headers

                blocks = get(
                    f"https://{blocker}/api/v1/instance/domain_blocks", headers=reqheaders, timeout=5, allow_redirects=False
                ).json()
                for block in blocks:
                    entry = {'domain': block['domain'], 'hash': block['digest'], 'reason': block['comment']}
                    if block['severity'] == 'suspend':
                        json['reject'].append(entry)
                    elif block['severity'] == 'silence':
                        json['followers_only'].append(entry)
                    elif block['severity'] == 'reject_media':
                        json['media_removal'].append(entry)
                    elif block['severity'] == 'reject_reports':
                        json['report_removal'].append(entry)
            except:
                json = get_mastodon_blocks(blocker)

            for block_level, blocks in json.items():
                for instance in blocks:
                    blocked, blocked_hash, reason = instance.values()
                    blocked = tidyup(blocked)
                    if blocked.count("*") <= 1 and blocked.startswith("*"):
                        c.execute(
                            "select hash from instances where hash = ?", (blocked_hash,)
                        )
                        if c.fetchone() == None:
                            c.execute(
                                "insert into instances select ?, ?, ?",
                                (blocked, get_hash(blocked), get_type(blocked)),
                            )
                    else:
                        # Doing the hash search for instance names as well to tidy up DB
                        c.execute(
                            "select domain from instances where hash = ?", (blocked_hash,)
                        )
                        searchres = c.fetchone()
                        if searchres != None:
                            blocked = searchres[0]
                        else:
                            # Apparently, some instances return incorrect hashes for whatever reason
                            # I've tested one of them, and those hashes correspond to the already obscured domain
                            # That doesn't make any sense unless someone obscured the domain themselves and put it into the blocklist, but whatever
                            c.execute(
                                "select domain from instances where domain like ? order by rowid limit 1", (blocked.replace("*", "_"),)
                            )
                            searchres = c.fetchone()
                            if searchres != None:
                                blocked = searchres[0]

                    timestamp = int(time())
                    c.execute(
                        "select * from blocks where blocker = ? and blocked = ? and block_level = ?",
                        (blocker, blocked if blocked.count("*") <= 1 else blocked_hash, block_level),
                    )
                    if c.fetchone() == None:
                        c.execute(
                            "insert into blocks select ?, ?, ?, ?, ?, ?",
                            (
                                blocker,
                                blocked if blocked.count("*") <= 1 else blocked_hash,
                                reason,
                                block_level,
                                timestamp,
                                timestamp,
                            ),
                        )
                        if block_level == "reject":
                            blockdict.append(
                                {
                                    "blocked": blocked,
                                    "reason": reason
                                })
                    else:
                        c.execute(
                            "update blocks set last_seen = ? where blocker = ? and blocked = ? and block_level = ?",
                            (timestamp, blocker, blocked if blocked.count("*") <= 1 else blocked_hash, block_level),
                        )
                    if reason != '':
                        c.execute(
                            "update blocks set reason = ? where blocker = ? and blocked = ? and block_level = ? and reason = ''",
                            (reason, blocker, blocked if blocked.count("*") <= 1 else blocked_hash, block_level),
                        )
            conn.commit()
        except Exception as e:
            print("error:", e, blocker)
    elif software == "friendica" or software == "misskey":
        try:
            if software == "friendica":
                json = get_friendica_blocks(blocker)
            elif software == "misskey":
                json = get_pisskey_blocks(blocker)
            for block_level, blocks in json.items():
                for instance in blocks:
                    blocked, reason = instance.values()
                    blocked = tidyup(blocked)

                    if blocked.count("*") > 0:
                        # Some friendica servers also obscure domains without hash
                        c.execute(
                            "select domain from instances where domain like ? order by rowid limit 1", (blocked.replace("*", "_"),)
                        )
                        searchres = c.fetchone()
                        if searchres != None:
                            blocked = searchres[0]

                    if blocked.count("?") > 0:
                        # Some obscure them with question marks, not sure if that's dependent on version or not
                        c.execute(
                            "select domain from instances where domain like ? order by rowid limit 1", (blocked.replace("?", "_"),)
                        )
                        searchres = c.fetchone()
                        if searchres != None:
                            blocked = searchres[0]

                    timestamp = int(time())
                    c.execute(
                        "select * from blocks where blocker = ? and blocked = ?",
                        (blocker, blocked),
                    )
                    if c.fetchone() == None:
                        c.execute(
                            "insert into blocks select ?, ?, ?, ?, ?, ?",
                            (
                                blocker,
                                blocked,
                                reason,
                                block_level,
                                timestamp,
                                timestamp
                            ),
                        )
                        if block_level == "reject":
                            blockdict.append(
                                {
                                    "blocked": blocked,
                                    "reason": reason
                                })
                    else:
                        c.execute(
                            "update blocks set last_seen = ? where blocker = ? and blocked = ? and block_level = ?",
                            (timestamp, blocker, blocked, block_level),
                        )
                    if reason != '':
                        c.execute(
                            "update blocks set reason = ? where blocker = ? and blocked = ? and block_level = ? and reason = ''",
                            (reason, blocker, blocked, block_level),
                        )
            conn.commit()
        except Exception as e:
            print("error:", e, blocker)
    elif software == "gotosocial":
        try:
            # Blocks
            federation = get(
                f"https://{blocker}/api/v1/instance/peers?filter=suspended", headers=headers, timeout=5, allow_redirects=False
            ).json()
            for peer in federation:
                blocked = peer["domain"].lower()

                if blocked.count("*") > 0:
                    # GTS does not have hashes for obscured domains, so we have to guess it
                    c.execute(
                        "select domain from instances where domain like ? order by rowid limit 1", (blocked.replace("*", "_"),)
                    )
                    searchres = c.fetchone()
                    if searchres != None:
                        blocked = searchres[0]

                c.execute(
                    "select domain from instances where domain = ?", (blocked,)
                )
                if c.fetchone() == None:
                    c.execute(
                        "insert into instances select ?, ?, ?",
                        (blocked, get_hash(blocked), get_type(blocked)),
                    )
                c.execute(
                    "select * from blocks where blocker = ? and blocked = ? and block_level = ?",
                    (blocker, blocked, "reject"),
                )
                timestamp = int(time())
                if c.fetchone() == None:
                    c.execute(
                        "insert into blocks select ?, ?, ?, ?, ?, ?",
                           (blocker, blocked, "", "reject", timestamp, timestamp),
                    )
                    blockdict.append(
                        {
                            "blocked": blocked,
                            "reason": None
                        })
                else:
                    c.execute(
                        "update blocks set last_seen = ? where blocker = ? and blocked = ? and block_level = ?",
                        (timestamp, blocker, blocked, "reject"),
                    )
                if "public_comment" in peer:
                    reason = peer["public_comment"]
                    c.execute(
                        "update blocks set reason = ? where blocker = ? and blocked = ? and block_level = ? and reason = ''",
                        (reason, blocker, blocked, "reject"),
                    )
                    for entry in blockdict:
                        if entry["blocked"] == blocked:
                            entry["reason"] = reason
            conn.commit()
        except Exception as e:
            print("error:", e, blocker)
    elif software == "lemmy":
        # looks like there's no reason field or obscured domain names yet
        try:
            # Blocks
            federation = get(
                f"https://{blocker}/api/v3/site", headers=headers, timeout=5, allow_redirects=False
            ).json()
            blocks = federation['federated_instances']['blocked']
            for blocked in blocks:
                blocked = tidyup(blocked)

                c.execute(
                    "select domain from instances where domain = ?", (blocked,)
                )
                if c.fetchone() == None:
                    c.execute(
                        "insert into instances select ?, ?, ?",
                        (blocked, get_hash(blocked), get_type(blocked)),
                    )
                c.execute(
                    "select * from blocks where blocker = ? and blocked = ? and block_level = ?",
                    (blocker, blocked, "reject"),
                )
                timestamp = int(time())
                if c.fetchone() == None:
                    c.execute(
                        "insert into blocks select ?, ?, ?, ?, ?, ?",
                           (blocker, blocked, "", "reject", timestamp, timestamp),
                    )
                    blockdict.append(
                        {
                            "blocked": blocked,
                            "reason": None
                        })
                else:
                    c.execute(
                        "update blocks set last_seen = ? where blocker = ? and blocked = ? and block_level = ?",
                        (timestamp, blocker, blocked, "reject"),
                    )
            conn.commit()
        except Exception as e:
            print("error:", e, blocker)

    if config["bot_enabled"] and len(blockdict) > 0:
        send_bot_post(blocker, blockdict)
    blockdict = []

conn.close()
