import sqlite3
from datetime import datetime

DB_NAME = "scanner.db"


def get_conn():
    return sqlite3.connect(DB_NAME)

def init_db():

    conn = get_conn()
    c = conn.cursor()

    c.execute("PRAGMA foreign_keys = ON")

    # targets

    c.execute("""
    CREATE TABLE IF NOT EXISTS targets (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        target TEXT UNIQUE,
        target_type TEXT,

        last_scan DATETIME
    )
    """)

    # scans (история запусков)

    c.execute("""
    CREATE TABLE IF NOT EXISTS scans (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        target_id INTEGER,

        scanner TEXT,
        arguments TEXT,

        started_at DATETIME,
        finished_at DATETIME,

        status TEXT,
        raw_output TEXT,

        FOREIGN KEY(target_id) REFERENCES targets(id)
    )
    """)

    # services (Nmap)

    c.execute("""
    CREATE TABLE IF NOT EXISTS services (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        target_id INTEGER,

        port INTEGER,
        protocol TEXT,

        state TEXT,
        service TEXT,
        product TEXT,
        version TEXT,
        extra_info TEXT,

        last_updated DATETIME,

        FOREIGN KEY(target_id) REFERENCES targets(id),

        UNIQUE(target_id, port, protocol)
    )
    """)

    # Nikto

    c.execute("""
    CREATE TABLE IF NOT EXISTS web_issues (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        target_id INTEGER,

        port INTEGER,
        url TEXT,

        issue TEXT,
        description TEXT,
        reference TEXT,
        severity TEXT,

        last_updated DATETIME,

        FOREIGN KEY(target_id) REFERENCES targets(id),

        UNIQUE(target_id, url, issue)
    )
    """)

    # ZAP

    c.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        target_id INTEGER,

        url TEXT,
        parameter TEXT,

        alert TEXT,
        description TEXT,

        attack TEXT,
        evidence TEXT,

        risk TEXT,
        confidence TEXT,

        solution TEXT,

        last_updated DATETIME,

        FOREIGN KEY(target_id) REFERENCES targets(id),

        UNIQUE(target_id, url, alert, parameter)
    )
    """)

    conn.commit()
    conn.close()


# --------------------------------------------------
# Работа с targets
# --------------------------------------------------

def get_or_create_target(target):

    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT id FROM targets WHERE target=?", (target,))
    row = c.fetchone()

    if row:

        target_id = row[0]

    else:

        target_type = "url" if "http" in target else "ip"

        c.execute(
            "INSERT INTO targets(target,target_type) VALUES(?,?)",
            (target, target_type)
        )

        target_id = c.lastrowid

    conn.commit()
    conn.close()

    return target_id


# --------------------------------------------------
# История сканирований
# --------------------------------------------------

def create_scan(target_id, scanner, args):

    conn = get_conn()
    c = conn.cursor()

    started = datetime.now()

    c.execute("""

    INSERT INTO scans
    (target_id, scanner, arguments, started_at, status)

    VALUES(?,?,?,?,?)

    """, (

        target_id,
        scanner,
        " ".join(args),
        started,
        "running"

    ))

    scan_id = c.lastrowid

    conn.commit()
    conn.close()

    return scan_id


def finish_scan(scan_id, output):

    conn = get_conn()
    c = conn.cursor()

    finished = datetime.now()

    c.execute("""

    UPDATE scans

    SET
        finished_at=?,
        status=?,
        raw_output=?

    WHERE id=?

    """, (

        finished,
        "completed",
        output,
        scan_id

    ))

    conn.commit()
    conn.close()


# --------------------------------------------------
# Nmap services
# --------------------------------------------------

def save_services(target_id, services):

    conn = get_conn()
    c = conn.cursor()

    for s in services:

        c.execute("""

        INSERT INTO services
        (target_id,port,protocol,state,service,product,version,extra_info,last_updated)

        VALUES(?,?,?,?,?,?,?,?,datetime('now'))

        ON CONFLICT(target_id,port,protocol)

        DO UPDATE SET

            state=excluded.state,
            service=excluded.service,
            product=excluded.product,
            version=excluded.version,
            extra_info=excluded.extra_info,
            last_updated=datetime('now')

        """, (

            target_id,
            s.get("port"),
            s.get("protocol"),
            s.get("state"),
            s.get("service"),
            s.get("product"),
            s.get("version"),
            s.get("extra_info")

        ))

    conn.commit()
    conn.close()


# --------------------------------------------------
# Nikto
# --------------------------------------------------

def save_web_issues(target_id, issues):

    conn = get_conn()
    c = conn.cursor()

    for i in issues:

        c.execute("""

        INSERT INTO web_issues
        (target_id,port,url,issue,description,reference,severity,last_updated)

        VALUES(?,?,?,?,?,?,?,datetime('now'))

        ON CONFLICT(target_id,url,issue)

        DO UPDATE SET

            description=excluded.description,
            reference=excluded.reference,
            severity=excluded.severity,
            last_updated=datetime('now')

        """, (

            target_id,
            i.get("port"),
            i.get("url"),
            i.get("issue"),
            i.get("description"),
            i.get("reference"),
            i.get("severity")

        ))

    conn.commit()
    conn.close()


# --------------------------------------------------
# ZAP
# --------------------------------------------------

def save_vulnerabilities(target_id, vulns):

    conn = get_conn()
    c = conn.cursor()

    for v in vulns:

        c.execute("""

        INSERT INTO vulnerabilities
        (target_id,url,parameter,alert,description,attack,evidence,risk,confidence,solution,last_updated)

        VALUES(?,?,?,?,?,?,?,?,?,?,datetime('now'))

        ON CONFLICT(target_id,url,alert,parameter)

        DO UPDATE SET

            description=excluded.description,
            attack=excluded.attack,
            evidence=excluded.evidence,
            risk=excluded.risk,
            confidence=excluded.confidence,
            solution=excluded.solution,
            last_updated=datetime('now')

        """, (

            target_id,
            v.get("url"),
            v.get("parameter"),
            v.get("alert"),
            v.get("description"),
            v.get("attack"),
            v.get("evidence"),
            v.get("risk"),
            v.get("confidence"),
            v.get("solution")

        ))

    conn.commit()
    conn.close()