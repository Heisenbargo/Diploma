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

    # Wapiti

    c.execute("""
    CREATE TABLE IF NOT EXISTS wapiti_issues (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        target_id INTEGER,

        type TEXT,
        url TEXT,
        parameter TEXT,
        method TEXT,

        info TEXT,
        level TEXT,
        reference TEXT,
              
        solution TEXT,

        last_updated DATETIME,

        FOREIGN KEY(target_id) REFERENCES targets(id),

        UNIQUE(target_id, url, parameter, type)
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

def get_services(target_id):

    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        SELECT port, state, service, version
        FROM services
        WHERE target_id=?
    """, (target_id,))

    rows = c.fetchall()

    conn.close()

    return [
        {
            "port": r[0],
            "state": r[1],
            "service": r[2],
            "version": r[3]
        }
        for r in rows
    ]
# --------------------------------------------------
# RECOMENDATIONS Nmap
# --------------------------------------------------

def get_nmap_recommendations(target_id):

    services = get_services(target_id)

    recommendations = []

    for s in services:

        port = s["port"]
        service = s["service"]

        rec = f"Порт {port} ({service}): "

        if service in ["http", "https"]:
            rec += "Рекомендуется провести анализ веб-приложения (Wapiti/ZAP)"
        elif service == "ssh":
            rec += "Ограничить доступ по IP, отключить root login"
        elif service == "ftp":
            rec += "Отключить анонимный доступ и использовать SFTP"
        elif service == "telnet":
            rec += "Отключить Telnet и использовать SSH"
        else:
            rec += "Проверить необходимость открытого порта и ограничить доступ"

        recommendations.append(rec)

    return recommendations

# --------------------------------------------------
# Wapiti
# --------------------------------------------------

def save_wapiti_issues(target_id, issues):

    conn = get_conn()
    c = conn.cursor()

    for i in issues:

        c.execute("""
        INSERT INTO wapiti_issues
        (target_id, type, url, parameter, method, info, level, reference, solution, last_updated)

        VALUES(?,?,?,?,?,?,?,?,?, datetime('now'))

        ON CONFLICT(target_id, url, parameter, type)

        DO UPDATE SET
            method=excluded.method,
            info=excluded.info,
            level=excluded.level,
            reference=excluded.reference,
            solution=excluded.solution,
            last_updated=datetime('now')
        """, (

            target_id,
            i.get("type"),
            i.get("url"),
            i.get("parameter"),
            i.get("method"),
            i.get("info"),
            i.get("level"),
            i.get("reference"),
            i.get("solution")

        ))

    conn.commit()
    conn.close()

def get_wapiti_issues(target_id):

    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT url,type,info,level FROM wapiti_issues WHERE target_id=?", (target_id,))
    rows = c.fetchall()

    conn.close()

    return [
        {"url": r[0], "type": r[1], "info": r[2], "level": r[3]}
        for r in rows
    ]

# --------------------------------------------------
# RECOMENDATIONS Wapiti
# --------------------------------------------------

def get_wapiti_recommendations(target_id):

    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        SELECT solution
        FROM wapiti_issues
        WHERE target_id=? AND solution IS NOT NULL
    """, (target_id,))

    rows = c.fetchall()
    conn.close()

    return [
        {
            "url": r[0],
            "issue": r[1],
            "solution": r[2],
            "severity": r[3]
        }
        for r in rows
    ]

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

def get_vulnerabilities(target_id):

    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        SELECT url, alert, description, risk
        FROM vulnerabilities
        WHERE target_id=?
    """, (target_id,))

    rows = c.fetchall()

    conn.close()

    return [
        {
            "url": r[0],
            "alert": r[1],
            "description": r[2],
            "risk": r[3]
        }
        for r in rows
    ]

# --------------------------------------------------
# RECOMENDATIONS ZAP
# --------------------------------------------------

def get_zap_recommendations(target_id):

    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        SELECT url, alert, solution, risk
        FROM vulnerabilities
        WHERE target_id=? AND solution IS NOT NULL
    """, (target_id,))

    rows = c.fetchall()
    conn.close()

    return [
        {
            "url": r[0],
            "alert": r[1],
            "solution": r[2],
            "risk": r[3]
        }
        for r in rows
    ]