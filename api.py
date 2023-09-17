import uvicorn
from fastapi import FastAPI, Request, HTTPException, responses, Query
import sqlite3
from hashlib import sha256
from fastapi.templating import Jinja2Templates
from requests import get
from json import loads
from re import sub
from datetime import datetime
from email import utils

with open("config.json") as f:
    config = loads(f.read())
    base_url = config["base_url"]
    port = config["port"]
app = FastAPI(docs_url=base_url+"/docs", redoc_url=base_url+"/redoc")
templates = Jinja2Templates(directory=".")

def get_hash(domain: str) -> str:
    return sha256(domain.encode("utf-8")).hexdigest()

@app.get(base_url+"/info")
def info():
    conn = sqlite3.connect("blocks.db")
    c = conn.cursor()
    c.execute("select (select count(domain) from instances), (select count(domain) from instances where software in ('pleroma', 'mastodon', 'misskey', 'gotosocial', 'friendica', 'lemmy')), (select count(blocker) from blocks)")
    known, indexed, blocks = c.fetchone()
    c.close()
    return {
        "known_instances": known,
        "indexed_instances": indexed,
        "blocks_recorded": blocks
    }

@app.get(base_url+"/top")
def top(blocked: int = None, blockers: int = None):
    conn = sqlite3.connect("blocks.db")
    c = conn.cursor()
    if blocked == None and blockers == None:
        raise HTTPException(status_code=400, detail="No filter specified")
    elif blocked != None:
        if blocked > 500:
            raise HTTPException(status_code=400, detail="Too many results")
        c.execute("select blocked, count(blocked) from blocks where block_level = 'reject' group by blocked order by count(blocked) desc limit ?", (blocked,))
    elif blockers != None:
        if blockers > 500:
            raise HTTPException(status_code=400, detail="Too many results")
        c.execute("select blocker, count(blocker) from blocks where block_level = 'reject' group by blocker order by count(blocker) desc limit ?", (blockers,))
    scores = c.fetchall()
    c.close()

    scoreboard = []
    print(scores)
    for domain, highscore in scores:
        scoreboard.append({"domain": domain, "highscore": highscore})

    return scoreboard

@app.get(base_url+"/top/weighted")
def weighted():
    conn = sqlite3.connect("blocks.db")
    c = conn.cursor()
    # trying to make the limit adjustable makes the app crash with `sqlite3.IntegrityError: datatype mismatch`, so rolling with hardcoded one
    c.execute("with weighted as (SELECT blocker, count(*) as instance_weight FROM blocks where block_level = 'reject' GROUP BY blocker) SELECT rank() OVER (order by sum(1 / log(instance_weight)) desc) as rank, b.blocked, count(*) as total_blocks, sum(1 / log(instance_weight + 1)) as weighted_score FROM blocks b JOIN weighted USING (blocker) GROUP BY b.blocked order by weighted_score DESC LIMIT 100")
    scores = c.fetchall()
    c.close()

    scoreboard = []
    print(scores)
    for rank, domain, blocks, weight in scores:
        scoreboard.append({"domain": domain, "blocks": blocks, "weight": round(weight, 4)})

    return scoreboard

@app.get(base_url+"/api")
def blocked(domain: str = None, reason: str = None, reverse: str = None):
    if domain == None and reason == None and reverse == None:
        raise HTTPException(status_code=400, detail="No filter specified")
    if reason != None:
        reason = sub("(%|_)", "", reason)
        if len(reason) < 3:
            raise HTTPException(status_code=400, detail="Keyword is shorter than three characters")
    conn = sqlite3.connect("blocks.db")
    c = conn.cursor()
    if domain != None:
        wildchar = "*." + ".".join(domain.split(".")[-domain.count("."):])
        punycode = domain.encode('idna').decode('utf-8')
        c.execute("select blocker, blocked, block_level, reason, first_added, last_seen from blocks where blocked = ? or blocked = ? or blocked = ? or blocked = ? or blocked = ? or blocked = ? order by first_added asc",
                  (domain, "*." + domain, wildchar, get_hash(domain), punycode, "*." + punycode))
    elif reverse != None:
        c.execute("select blocker, blocked, block_level, reason, first_added, last_seen from blocks where blocker = ? order by first_added asc", (reverse,))
    else:
        c.execute("select blocker, blocked, block_level, reason, first_added, last_seen from blocks where reason like ? and reason != '' order by first_added asc", ("%"+reason+"%",))
    blocks = c.fetchall()
    c.close()

    result = {}
    for blocker, blocked, block_level, reason, first_added, last_seen in blocks:
        entry = {"blocker": blocker, "blocked": blocked, "reason": reason, "first_added": first_added, "last_seen": last_seen}
        if block_level in result:
            result[block_level].append(entry)
        else:
            result[block_level] = [entry]

    return result

@app.get(base_url+"/scoreboard")
def index(request: Request, blockers: int = None, blocked: int = None):
    if blockers == None and blocked == None:
        raise HTTPException(status_code=400, detail="No filter specified")
    elif blockers != None:
        scores = get(f"http://127.0.0.1:{port}{base_url}/top?blockers={blockers}")
    elif blocked != None:
        scores = get(f"http://127.0.0.1:{port}{base_url}/top?blocked={blocked}")
    if scores != None:
        if not scores.ok:
            raise HTTPException(status_code=blocks.status_code, detail=blocks.text)
        scores = scores.json()
    return templates.TemplateResponse("index.html", {"request": request, "scoreboard": True, "blockers": blockers, "blocked": blocked, "scores": scores})

@app.get(base_url+"/weighted")
def index(request: Request):
    scores = get(f"http://127.0.0.1:{port}{base_url}/top/weighted")
    if scores != None:
        if not scores.ok:
            raise HTTPException(status_code=blocks.status_code, detail=blocks.text)
        scores = scores.json()
    return templates.TemplateResponse("index.html", {"request": request, "weighted": True, "scores": scores})

@app.get(base_url+"/")
def index(request: Request, domain: str = None, reason: str = None, reverse: str = None):
    if domain == "" or reason == "" or reverse == "":
        return responses.RedirectResponse("/")
    info = None
    blocks = None
    if domain == None and reason == None and reverse == None:
        info = get(f"http://127.0.0.1:{port}{base_url}/info")
        if not info.ok:
            raise HTTPException(status_code=info.status_code, detail=info.text)
        info = info.json()
    elif domain != None:
        blocks = get(f"http://127.0.0.1:{port}{base_url}/api?domain={domain}")
    elif reason != None:
        blocks = get(f"http://127.0.0.1:{port}{base_url}/api?reason={reason}")
    elif reverse != None:
        blocks = get(f"http://127.0.0.1:{port}{base_url}/api?reverse={reverse}")
    if blocks != None:
        if not blocks.ok:
            raise HTTPException(status_code=blocks.status_code, detail=blocks.text)
        blocks = blocks.json()
        for block_level in blocks:
            for block in blocks[block_level]:
                block["first_added"] = datetime.utcfromtimestamp(block["first_added"]).strftime('%Y-%m-%d %H:%M')
                block["last_seen"] = datetime.utcfromtimestamp(block["last_seen"]).strftime('%Y-%m-%d %H:%M')

    return templates.TemplateResponse("index.html", {"request": request, "domain": domain, "blocks": blocks, "reason": reason, "reverse": reverse, "info": info})

@app.get(base_url+"/api/mutual")
def mutual(domains: list[str] = Query()):
    """Return 200 if federation is open between the two, 4xx otherwise"""
    conn = sqlite3.connect('blocks.db')
    c = conn.cursor()
    c.execute(
        "SELECT block_level FROM blocks " \
        "WHERE ((blocker = :a OR blocker = :b) AND (blocked = :b OR blocked = :a OR blocked = :aw OR blocked = :bw)) " \
        "AND block_level = 'reject' " \
        "LIMIT 1",
        {
            "a": domains[0],
            "b": domains[1],
            "aw": "*." + domains[0],
            "bw": "*." + domains[1],
        },
    )
    res = c.fetchone()
    c.close()
    if res is not None:
        # Blocks found
        return responses.JSONResponse(status_code=418, content={})
    # No known blocks
    return responses.JSONResponse(status_code=200, content={})

@app.get(base_url+"/rss")
def rss(request: Request, domain: str = None):
    conn = sqlite3.connect("blocks.db")
    c = conn.cursor()
    if domain != None:
        wildchar = "*." + ".".join(domain.split(".")[-domain.count("."):])
        punycode = domain.encode('idna').decode('utf-8')
        c.execute("select blocker, blocked, block_level, reason, first_added, last_seen from blocks where blocked = ? or blocked = ? or blocked = ? or blocked = ? or blocked = ? or blocked = ? order by first_added desc limit 50",
                  (domain, "*." + domain, wildchar, get_hash(domain), punycode, "*." + punycode))
    else:
        c.execute("select blocker, blocked, block_level, reason, first_added, last_seen from blocks order by first_added desc limit 50")
    blocks = c.fetchall()
    c.close()

    result = []
    for blocker, blocked, block_level, reason, first_added, last_seen in blocks:
        first_added = utils.format_datetime(datetime.fromtimestamp(first_added))
        if reason == None or reason == '':
            reason = "No reason provided."
        else:
            reason = "Provided reason: '" + reason + "'"
        result.append({"blocker": blocker, "blocked": blocked, "block_level": block_level, "reason": reason, "first_added": first_added})

    timestamp = utils.format_datetime(datetime.now())

    return templates.TemplateResponse("rss.xml", {"request": request, "timestamp": timestamp, "domain": domain, "blocks": result}, headers={"Content-Type": "application/rss+xml"})

if __name__ == "__main__":
    uvicorn.run("api:app", host="127.0.0.1", port=port, log_level="info")
