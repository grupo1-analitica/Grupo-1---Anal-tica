import os, re, time, math, datetime, secrets, smtplib, ssl, html as _html
from email.message import EmailMessage
from decimal import Decimal, InvalidOperation
import pyodbc
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=bool(os.environ.get("WEBSITE_SITE_NAME")))
SCHEMA, PAGE = "G1", 20


def get_conn():
    d = "ODBC Driver 18 for SQL Server" if "ODBC Driver 18 for SQL Server" in pyodbc.drivers() else "ODBC Driver 17 for SQL Server"
    cs = (f"DRIVER={{{d}}};SERVER={os.environ['DB_SERVER']};DATABASE={os.environ['DB_NAME']};"
          f"UID={os.environ['DB_USER']};PWD={{{os.environ['DB_PASSWORD']}}};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30")
    return pyodbc.connect(cs)


def run(sql, params=(), fetch=True):
    cn = get_conn()
    try:
        cur = cn.cursor()
        cur.execute(sql, params)
        rows = []
        if fetch and cur.description:
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        cn.commit()
        return rows
    finally:
        cn.close()


DDL = ("IF OBJECT_ID('G1.APP_USUARIOS','U') IS NULL CREATE TABLE G1.APP_USUARIOS ("
       "usuario_id INT IDENTITY(1,1) PRIMARY KEY, usuario VARCHAR(50) NOT NULL UNIQUE, nombre VARCHAR(100) NOT NULL, "
       "correo VARCHAR(150) NULL, rol VARCHAR(20) NOT NULL CHECK (rol IN ('administrador','supervisor','agente')), "
       "clave_hash VARCHAR(255) NOT NULL, activo BIT NOT NULL DEFAULT 1, creado DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME())")
MIGRA = [
    "IF COL_LENGTH('G1.APP_USUARIOS','debe_cambiar') IS NULL BEGIN "
    "ALTER TABLE G1.APP_USUARIOS ADD debe_cambiar BIT NOT NULL CONSTRAINT DF_APP_USR_dc DEFAULT 0; "
    "EXEC('UPDATE G1.APP_USUARIOS SET debe_cambiar=1 WHERE rol<>''administrador'''); END",
    "IF OBJECT_ID('G1.APP_SOLICITUDES','U') IS NULL CREATE TABLE G1.APP_SOLICITUDES ("
    "solicitud_id INT IDENTITY(1,1) PRIMARY KEY, nombre VARCHAR(100) NOT NULL, correo VARCHAR(150) NOT NULL, motivo VARCHAR(300) NULL, "
    "estado VARCHAR(12) NOT NULL DEFAULT 'pendiente', token CHAR(64) NOT NULL, creado DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(), "
    "resuelto DATETIME2 NULL, resuelto_por VARCHAR(50) NULL)",
    "IF OBJECT_ID('G1.APP_REPORTES_HIST','U') IS NULL CREATE TABLE G1.APP_REPORTES_HIST ("
    "fecha DATE NOT NULL PRIMARY KEY, clientes INT, activos INT, cancelados INT, tasa FLOAT, intervenciones INT, calificacion FLOAT)",
    "IF OBJECT_ID('G1.APP_ACTIVIDAD','U') IS NULL CREATE TABLE G1.APP_ACTIVIDAD ("
    "actividad_id INT IDENTITY(1,1) PRIMARY KEY, momento DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(), usuario VARCHAR(50) NOT NULL, "
    "accion VARCHAR(20) NOT NULL, entidad VARCHAR(30) NOT NULL, registro_id INT NULL)",
]
ROLES = ["administrador", "supervisor", "agente"]
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
VALIDEZ_SOLICITUD, DURACION_INVITADO = 30 * 60, 4 * 3600
PERMISOS = {
    "administrador": dict(ver="*", editar="*", eliminar="*"),
    "supervisor": dict(ver="*", editar={"intervenciones", "contratos"}, eliminar=set()),
    "agente": dict(ver={"intervenciones", "contratos", "clientes"}, editar={"intervenciones"}, eliminar=set()),
    "invitado": dict(ver=set(), editar=set(), eliminar=set()),
}
_estado = {"listo": False}


def iniciar():
    if not _estado["listo"]:
        run(DDL, fetch=False)
        for q in MIGRA: run(q, fetch=False)
        _estado["listo"] = run("SELECT COUNT(*) AS n FROM G1.APP_USUARIOS")[0]["n"] > 0
    return _estado["listo"]


def puede(accion, ent):
    p = PERMISOS.get(session.get("rol"), {}).get(accion, set())
    return p == "*" or ent in p


def requiere(*roles):
    if session.get("rol") not in roles: abort(403)


def csrf():
    if "_csrf" not in session: session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals.update(csrf=csrf, puede=puede)

F = lambda n, l, t, req=True, **k: dict(n=n, l=l, t=t, req=req, **k)
ENT = {
    "intervenciones": dict(t="Intervenciones", tabla="INTERVENCIONES", pk="intervencion_id", auto=False,
        buscar=["CAST(t.intervencion_id AS VARCHAR(20))", "CAST(t.cliente_id AS VARCHAR(20))", "CAST(t.contrato_id AS VARCHAR(20))"],
        extra=[("dias_atencion", "Días de atención", "DATEDIFF(day, t.fecha_contacto, t.fecha_cierre)")],
        chk=[("fecha_contacto", "fecha_cierre", "La fecha de cierre no puede ser anterior a la fecha de contacto")],
        campos=[F("cliente_id", "N.° de cliente", "int"),
                F("agente_id", "Agente", "sel", src=("AGENTES", "agente_id", "nombre")),
                F("solucion_id", "Tipo de solución", "sel", src=("TIPOS_SOLUCION", "solucion_id", "descripcion")),
                F("resultado_id", "Resultado", "sel", src=("RESULTADOS_INTERVENCION", "resultado_id", "descripcion")),
                F("canal_id", "Canal", "sel", src=("CANALES", "canal_id", "nombre")),
                F("fecha_contacto", "Fecha de contacto", "date"), F("hora_contacto", "Hora de contacto", "time"),
                F("fecha_cierre", "Fecha de cierre", "date", False), F("contrato_id", "N.° de contrato", "int", False)]),
    "contratos": dict(t="Contratos", tabla="CONTRATOS", pk="contrato_id", auto=True,
        buscar=["CAST(t.contrato_id AS VARCHAR(20))", "CAST(t.cliente_id AS VARCHAR(20))", "t.estado"],
        chk=[("fecha_inicio", "fecha_fin", "La fecha fin no puede ser anterior a la fecha de inicio")],
        campos=[F("plan_id", "Plan", "sel", src=("PLANES", "plan_id", "nombre_plan")), F("cliente_id", "N.° de cliente", "int"),
                F("fecha_inicio", "Fecha de inicio", "date"), F("fecha_fin", "Fecha fin", "date", False),
                F("estado", "Estado", "sel", opts=[("activo", "activo"), ("cancelado", "cancelado")])]),
    "clientes": dict(t="Clientes", tabla="CLIENTES", pk="cliente_id", auto=False,
        buscar=["t.nombre", "CAST(t.cliente_id AS VARCHAR(20))"],
        campos=[F("nombre", "Nombre", "text", max=120), F("fecha_alta", "Fecha de alta", "date")]),
    "agentes": dict(t="Agentes", tabla="AGENTES", pk="agente_id", auto=False, buscar=["t.nombre"], unico="nombre",
        campos=[F("nombre", "Nombre", "text", max=100), F("canal_id", "Canal", "sel", src=("CANALES", "canal_id", "nombre")),
                F("fecha_ingreso", "Fecha de ingreso", "date")]),
    "planes": dict(t="Planes", tabla="PLANES", pk="plan_id", auto=False, buscar=["t.nombre_plan"], unico="nombre_plan",
        campos=[F("nombre_plan", "Nombre del plan", "text", max=50), F("precio_mensual", "Precio mensual", "num")]),
}
for _e in ENT.values():
    _e.setdefault("extra", []); _e.setdefault("chk", [])


def opciones(c):
    if c.get("opts"):
        return c["opts"]
    tb, i, l = c["src"]
    return [(r["v"], r["l"]) for r in run(f"SELECT {i} AS v, {l} AS l FROM {SCHEMA}.{tb} ORDER BY {l}")]


def leer(e, form, id):
    v, errs = {}, []
    for c in e["campos"]:
        x = (form.get(c["n"]) or "").strip()
        if not x:
            if c["req"]: errs.append(f"{c['l']} es obligatorio")
            v[c["n"]] = None
            continue
        try:
            if c["t"] == "int" or (c["t"] == "sel" and c.get("src")): x = int(x)
            elif c["t"] == "num":
                x = Decimal(x)
                if x < 0: raise ValueError
            elif c["t"] == "text" and len(x) > c["max"]: errs.append(f"{c['l']}: máximo {c['max']} caracteres")
        except (ValueError, InvalidOperation):
            errs.append(f"{c['l']} no es válido")
        v[c["n"]] = x
    for a, b, m in e["chk"]:
        if v.get(a) and v.get(b) and v[b] < v[a]: errs.append(m)
    u = e.get("unico")
    if u and v.get(u) and not errs:
        n = run(f"SELECT COUNT(*) AS n FROM {SCHEMA}.{e['tabla']} WHERE LOWER({u})=LOWER(?) AND {e['pk']}<>?", [v[u], id or -1])[0]["n"]
        if n: errs.append("Ya existe un registro con ese nombre")
    return v, errs


def guardar(e, v, id):
    cols = [c["n"] for c in e["campos"]]; vals = [v[c] for c in cols]; T = f"{SCHEMA}.{e['tabla']}"; ph = ",".join("?" * len(cols))
    if id:
        run(f"UPDATE {T} SET {','.join(c + '=?' for c in cols)} WHERE {e['pk']}=?", vals + [id], fetch=False)
    elif e["auto"]:
        run(f"INSERT INTO {T} ({','.join(cols)}) VALUES ({ph})", vals, fetch=False)
    else:
        run(f"SET NOCOUNT ON; SET XACT_ABORT ON; BEGIN TRAN; DECLARE @id INT=(SELECT ISNULL(MAX({e['pk']}),0)+1 FROM {T} WITH (UPDLOCK,HOLDLOCK)); "
            f"INSERT INTO {T} ({e['pk']},{','.join(cols)}) VALUES (@id,{ph}); COMMIT;", vals, fetch=False)


PUBLICOS = {"login", "configurar", "invitado", "invitado_espera", "invitado_estado", "invitado_entrar"}


def base_url():
    u = os.environ.get("APP_URL")
    if u: return u.rstrip("/")
    r = request.url_root.rstrip("/")
    return r.replace("http://", "https://", 1) if os.environ.get("WEBSITE_SITE_NAME") else r


def hoy_lima():
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=5)).date()


def log_act(accion, entidad, rid=None):
    try:
        run("INSERT INTO G1.APP_ACTIVIDAD (usuario,accion,entidad,registro_id) VALUES (?,?,?,?)", [str(session.get("u", "?"))[:50], accion, entidad, rid], fetch=False)
    except Exception:
        pass


@app.before_request
def proteger():
    if request.endpoint in ("static", "reporte_enviar_token"): return
    if request.method == "POST" and request.form.get("_csrf") != session.get("_csrf"): abort(400)
    if request.endpoint != "configurar" and not iniciar(): return redirect(url_for("configurar"))
    if session.get("rol") == "invitado" and session.get("exp", 0) < time.time():
        session.clear(); flash("Tu acceso de invitado terminó. Solicita uno nuevo si lo necesitas.", "err"); return redirect(url_for("login"))
    if request.endpoint not in PUBLICOS and not session.get("u"):
        return redirect(url_for("login", next=request.path) if request.method == "GET" else url_for("login"))
    if session.get("dc") and request.endpoint not in ("cuenta", "logout"):
        flash("Por seguridad, cambia tu clave inicial antes de continuar.", "err"); return redirect(url_for("cuenta"))


@app.errorhandler(403)
def prohibido(e):
    return render_template("error.html", msg="No tienes permiso para esta acción."), 403


@app.errorhandler(400)
def invalido(e):
    return render_template("error.html", msg="La solicitud no es válida. Vuelve atrás y reintenta."), 400


@app.route("/configurar", methods=["GET", "POST"])
def configurar():
    if iniciar(): return redirect(url_for("login"))
    if request.method == "POST":
        f = request.form; cod = os.environ.get("SETUP_CODE")
        if not cod or not secrets.compare_digest(f.get("codigo", ""), cod): flash("Código de instalación incorrecto", "err")
        elif len(f.get("clave", "")) < 8 or not f.get("usuario", "").strip() or not f.get("nombre", "").strip():
            flash("Completa usuario y nombre; la clave debe tener al menos 8 caracteres", "err")
        else:
            run("INSERT INTO G1.APP_USUARIOS (usuario,nombre,correo,rol,clave_hash) VALUES (?,?,?,?,?)",
                [f["usuario"].strip().lower(), f["nombre"].strip(), f.get("correo") or None, "administrador", generate_password_hash(f["clave"])], fetch=False)
            _estado["listo"] = True; flash("Administrador creado. Ya puedes iniciar sesión.", "ok"); return redirect(url_for("login"))
    return render_template("configurar.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    sig = request.values.get("next", "")
    sig = sig if sig.startswith("/") and not sig.startswith("//") else ""
    if request.method == "POST":
        u = run("SELECT * FROM G1.APP_USUARIOS WHERE usuario=? AND activo=1", [request.form.get("u", "").strip().lower()])
        if u and check_password_hash(u[0]["clave_hash"], request.form.get("c", "")):
            dc = bool(u[0].get("debe_cambiar"))
            session.clear(); session.update(u=u[0]["usuario"], nombre=u[0]["nombre"], rol=u[0]["rol"], dc=dc); csrf()
            return redirect(url_for("cuenta") if dc else (sig or url_for("inicio")))
        flash("Usuario o clave incorrectos", "err")
    return render_template("login.html", sig=sig)


@app.route("/cuenta", methods=["GET", "POST"])
def cuenta():
    if session.get("rol") == "invitado": abort(403)
    if request.method == "POST":
        f = request.form; actual, nueva, rep_ = f.get("actual", ""), f.get("nueva", ""), f.get("repetir", "")
        r = run("SELECT clave_hash FROM G1.APP_USUARIOS WHERE usuario=?", [session["u"]])
        if not r or not check_password_hash(r[0]["clave_hash"], actual): flash("La clave actual no es correcta", "err")
        elif len(nueva) < 8: flash("La clave nueva debe tener al menos 8 caracteres", "err")
        elif nueva != rep_: flash("La clave nueva y su repetición no coinciden", "err")
        elif nueva == actual: flash("La clave nueva debe ser distinta de la actual", "err")
        else:
            run("UPDATE G1.APP_USUARIOS SET clave_hash=?, debe_cambiar=0 WHERE usuario=?", [generate_password_hash(nueva), session["u"]], fetch=False)
            session["dc"] = False; flash("Clave actualizada correctamente", "ok"); return redirect(url_for("inicio"))
    return render_template("cuenta.html")


@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))


@app.route("/usuarios")
def usuarios():
    requiere("administrador")
    return render_template("usuarios.html", rows=run("SELECT usuario_id,usuario,nombre,correo,rol,activo FROM G1.APP_USUARIOS ORDER BY usuario"))


@app.route("/usuarios/nuevo", methods=["GET", "POST"])
@app.route("/usuarios/<int:id>/editar", methods=["GET", "POST"])
def usuario_form(id=None):
    requiere("administrador")
    d = {}
    if request.method == "POST":
        f = request.form; d = f.to_dict(); errs = []
        usr = f.get("usuario", "").strip().lower(); clave = f.get("clave", ""); act = 1 if f.get("activo") else 0
        if not usr or not f.get("nombre", "").strip(): errs.append("Usuario y nombre son obligatorios")
        if f.get("rol") not in ROLES: errs.append("Rol no válido")
        if (not id or clave) and len(clave) < 8: errs.append("La clave debe tener al menos 8 caracteres")
        if not errs and run("SELECT COUNT(*) AS n FROM G1.APP_USUARIOS WHERE usuario=? AND usuario_id<>?", [usr, id or -1])[0]["n"]:
            errs.append("Ese usuario ya existe")
        if not errs and id:
            actual = run("SELECT usuario FROM G1.APP_USUARIOS WHERE usuario_id=?", [id])
            if actual and actual[0]["usuario"] == session["u"] and (f["rol"] != "administrador" or not act):
                errs.append("No puedes quitarte el rol de administrador ni desactivarte a ti mismo")
        if not errs:
            v = [usr, f["nombre"].strip(), f.get("correo") or None, f["rol"], act]
            if id:
                mismo = bool(run("SELECT 1 AS x FROM G1.APP_USUARIOS WHERE usuario_id=? AND usuario=?", [id, session["u"]]))
                run("UPDATE G1.APP_USUARIOS SET usuario=?,nombre=?,correo=?,rol=?,activo=?" + (",clave_hash=?,debe_cambiar=?" if clave else "") + " WHERE usuario_id=?",
                    v + ([generate_password_hash(clave), 0 if mismo else 1] if clave else []) + [id], fetch=False)
            else:
                run("INSERT INTO G1.APP_USUARIOS (usuario,nombre,correo,rol,activo,clave_hash,debe_cambiar) VALUES (?,?,?,?,?,?,1)", v + [generate_password_hash(clave)], fetch=False)
            flash("Usuario guardado", "ok"); return redirect(url_for("usuarios"))
        for m in errs: flash(m, "err")
    elif id:
        r = run("SELECT usuario,nombre,correo,rol,activo FROM G1.APP_USUARIOS WHERE usuario_id=?", [id])
        if not r: abort(404)
        d = r[0]
    else:
        d = {"activo": 1}
    return render_template("usuario_form.html", d=d, id=id, roles=ROLES)


@app.route("/")
def inicio():
    if session.get("rol") == "invitado": return redirect(url_for("dashboard"))
    return render_template("inicio.html", ENT={k: e for k, e in ENT.items() if puede("ver", k)}, dash=session.get("rol") in ("administrador", "supervisor"))


def datos_dashboard():
    k = run("SELECT (SELECT COUNT(*) FROM G1.CLIENTES) AS clientes, (SELECT COUNT(*) FROM G1.CONTRATOS WHERE estado='activo') AS activos, "
            "(SELECT COUNT(*) FROM G1.CONTRATOS WHERE estado='cancelado') AS cancelados, (SELECT COUNT(*) FROM G1.INTERVENCIONES) AS intervenciones, "
            "(SELECT AVG(CAST(calificacion AS FLOAT)) FROM G1.EVALUACIONES) AS calificacion")[0]
    par = lambda sql: [[r["etiqueta"], r["valor"]] for r in run(sql)]
    d = dict(
        motivos=par("SELECT m.descripcion AS etiqueta, COUNT(*) AS valor FROM G1.BAJAS b JOIN G1.MOTIVOS_BAJA m ON m.motivo_id=b.motivo_id GROUP BY m.descripcion ORDER BY valor DESC"),
        resultados=par("SELECT r.descripcion AS etiqueta, COUNT(*) AS valor FROM G1.INTERVENCIONES i JOIN G1.RESULTADOS_INTERVENCION r ON r.resultado_id=i.resultado_id GROUP BY r.descripcion ORDER BY valor DESC"),
        canales=par("SELECT c.nombre AS etiqueta, COUNT(*) AS valor FROM G1.INTERVENCIONES i JOIN G1.CANALES c ON c.canal_id=i.canal_id GROUP BY c.nombre ORDER BY valor DESC"),
        meses=par("SELECT TOP 12 CONVERT(char(7), fecha_baja, 120) AS etiqueta, COUNT(*) AS valor FROM G1.BAJAS GROUP BY CONVERT(char(7), fecha_baja, 120) ORDER BY etiqueta DESC")[::-1])
    tot = k["activos"] + k["cancelados"]
    k["tasa"] = round(100 * k["cancelados"] / tot, 2) if tot else 0
    k["calificacion"] = round(k["calificacion"] or 0, 2)
    return k, d


@app.route("/dashboard")
def dashboard():
    requiere("administrador", "supervisor", "invitado")
    k, d = datos_dashboard()
    return render_template("dashboard.html", k=k, d=d)


# ---------------- Reportes por correo ----------------
def guardar_snapshot(k, hoy):
    run("MERGE G1.APP_REPORTES_HIST AS t USING (SELECT CAST(? AS DATE) AS fecha) AS s ON t.fecha=s.fecha "
        "WHEN MATCHED THEN UPDATE SET clientes=?,activos=?,cancelados=?,tasa=?,intervenciones=?,calificacion=? "
        "WHEN NOT MATCHED THEN INSERT (fecha,clientes,activos,cancelados,tasa,intervenciones,calificacion) VALUES (s.fecha,?,?,?,?,?,?);",
        [hoy.isoformat()] + [k["clientes"], k["activos"], k["cancelados"], k["tasa"], k["intervenciones"], k["calificacion"]] * 2, fetch=False)


def datos_reporte():
    k, d = datos_dashboard()
    hoy = hoy_lima()
    prev = run("SELECT TOP 1 * FROM G1.APP_REPORTES_HIST WHERE fecha < CAST(? AS DATE) ORDER BY fecha DESC", [hoy.isoformat()])
    prev = prev[0] if prev else None
    delta = {c: (None if not prev or prev.get(c) is None else round(k[c] - prev[c], 2))
             for c in ("clientes", "activos", "cancelados", "tasa", "intervenciones", "calificacion")}
    ant = run("SELECT TOP 6 fecha, tasa FROM G1.APP_REPORTES_HIST WHERE fecha < CAST(? AS DATE) ORDER BY fecha DESC", [hoy.isoformat()])[::-1]
    tendencia = [[x["fecha"].strftime("%d/%m"), round(x["tasa"] or 0, 2)] for x in ant] + [[hoy.strftime("%d/%m"), k["tasa"]]]
    act = run("SELECT usuario, accion, entidad, COUNT(*) AS n FROM G1.APP_ACTIVIDAD WHERE momento > DATEADD(hour,-24,SYSUTCDATETIME()) "
              "GROUP BY usuario, accion, entidad ORDER BY n DESC")
    try:
        vig = run("SELECT TOP 5 i.contrato_id, cl.nombre, COUNT(*) AS n FROM G1.INTERVENCIONES i "
                  "JOIN G1.RESULTADOS_INTERVENCION r ON r.resultado_id=i.resultado_id JOIN G1.CONTRATOS c ON c.contrato_id=i.contrato_id "
                  "JOIN G1.CLIENTES cl ON cl.cliente_id=c.cliente_id WHERE c.estado='activo' AND r.descripcion<>'Retenido' "
                  "GROUP BY i.contrato_id, cl.nombre ORDER BY n DESC, i.contrato_id")
    except Exception:
        vig = []
    return dict(k=k, d=d, delta=delta, prev=prev, tendencia=tendencia, act=act, vig=vig, hoy=hoy)


def _barras(titulo, filas, color, fmt=lambda v: f"{v:,}"):
    if not filas: return ""
    mx = max(v for _, v in filas) or 1
    out = f'<tr><td style="padding:18px 24px 4px;font:700 15px Arial;color:#0b3d6b">{_html.escape(titulo)}</td></tr><tr><td style="padding:0 24px"><table width="100%" cellpadding="0" cellspacing="0">'
    for et, v in filas:
        w = max(int(100 * v / mx), 2)
        out += (f'<tr><td style="font:13px Arial;color:#334;padding:5px 8px 0 0;width:38%">{_html.escape(str(et))}</td>'
                f'<td style="padding:5px 0 0"><table width="100%" cellpadding="0" cellspacing="0"><tr>'
                f'<td width="{w}%" style="background:{color};height:14px;border-radius:7px;font-size:1px">&nbsp;</td>'
                f'<td style="font:700 12px Arial;color:#0b3d6b;padding-left:8px">{fmt(v)}</td><td width="{100-w}%"></td></tr></table></td></tr>')
    return out + "</table></td></tr>"


def _delta(v, malo_si_sube=False, neutral=False, dec=0, pct=False):
    if v is None: return '<div style="font:11px Arial;color:#99a;padding-top:4px">primer registro</div>'
    if v == 0: return '<div style="font:11px Arial;color:#889;padding-top:4px">sin cambios</div>'
    sube = v > 0
    col = "#1f7aec" if neutral else ("#e5484d" if sube == malo_si_sube else "#2fb67c")
    return f'<div style="font:11px Arial;color:{col};padding-top:4px">{"▲" if sube else "▼"} {abs(v):,.{dec}f}{"%" if pct else ""} vs. último reporte</div>'


def resumen_texto(r):
    dl, p = r["delta"], r["prev"]
    if not p: return "Es el primer reporte con historial: desde el próximo envío verás aquí qué cambió."
    partes = []
    for c, et in (("intervenciones", "intervenciones"), ("cancelados", "contratos cancelados"), ("activos", "contratos activos"), ("clientes", "clientes")):
        if dl[c]: partes.append(f"{dl[c]:+,.0f} {et}")
    if dl["tasa"]: partes.append(f"tasa de cancelación {dl['tasa']:+.2f} puntos")
    return f"Desde el reporte del {p['fecha']:%d/%m}: " + (", ".join(partes) if partes else "sin cambios en los indicadores") + "."


def correo_html(r, base):
    k, d, dl = r["k"], r["d"], r["delta"]
    def kpi(t, v, c, dlt):
        return (f'<td align="center" valign="top" style="background:#f2f6fc;border-radius:10px;padding:14px 6px;width:33%">'
                f'<div style="font:12px Arial;color:#667">{t}</div><div style="font:700 24px Arial;color:{c};padding-top:4px">{v}</div>{dlt}</td>')
    sp = '<td width="10"></td>'
    if r["act"]:
        act = "".join(f'<tr><td style="font:13px Arial;color:#334;padding:3px 0">• <b>{_html.escape(a["usuario"])}</b> {_html.escape(a["accion"])} {a["n"]} en {_html.escape(a["entidad"])}</td></tr>' for a in r["act"][:8])
    else:
        act = '<tr><td style="font:13px Arial;color:#889;padding:3px 0">Sin movimientos registrados en la app en las últimas 24 horas.</td></tr>'
    if r["vig"]:
        vig = "".join(f'<tr><td style="font:13px Arial;color:#334;padding:4px 0">Contrato <b>#{v["contrato_id"]}</b> · {_html.escape(v["nombre"] or "")}</td><td align="right" style="font:700 13px Arial;color:#e5484d">{v["n"]} sin retención</td></tr>' for v in r["vig"])
    else:
        vig = '<tr><td style="font:13px Arial;color:#889;padding:3px 0">Sin contratos para vigilar.</td></tr>'
    sec = lambda t: f'<tr><td style="padding:18px 24px 4px;font:700 15px Arial;color:#0b3d6b">{t}</td></tr>'
    return f"""<!doctype html><html><body style="margin:0;background:#e9eef6;padding:20px 0">
<table align="center" width="620" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:14px;overflow:hidden;max-width:96%">
<tr><td style="background:#0b3d6b;background-image:linear-gradient(90deg,#0b3d6b,#1f7aec);padding:26px 24px;color:#fff">
<div style="font:700 22px Arial">📡 Reporte diario de retención</div><div style="font:13px Arial;opacity:.9;padding-top:4px">Grupo 1 · Telecomunicaciones · {r["hoy"]:%d/%m/%Y}</div></td></tr>
<tr><td style="padding:16px 24px 0;font:13px Arial;color:#334"><b>Resumen:</b> {_html.escape(resumen_texto(r))}</td></tr>
<tr><td style="padding:14px 24px 0"><table width="100%" cellpadding="0" cellspacing="0"><tr>
{kpi("Clientes", f"{k['clientes']:,}", "#0b3d6b", _delta(dl['clientes'], neutral=True))}{sp}{kpi("Contratos activos", f"{k['activos']:,}", "#2fb67c", _delta(dl['activos']))}{sp}{kpi("Cancelados", f"{k['cancelados']:,}", "#e5484d", _delta(dl['cancelados'], malo_si_sube=True))}</tr>
<tr><td colspan="5" height="10"></td></tr><tr>
{kpi("Tasa de cancelación", f"{k['tasa']}%", "#e5484d", _delta(dl['tasa'], malo_si_sube=True, dec=2, pct=True))}{sp}{kpi("Intervenciones", f"{k['intervenciones']:,}", "#0b3d6b", _delta(dl['intervenciones'], neutral=True))}{sp}{kpi("Calificación prom.", k['calificacion'], "#f5a623", _delta(dl['calificacion'], dec=2))}</tr></table></td></tr>
{_barras("Tendencia de la tasa de cancelación", r["tendencia"], "#e5484d", lambda v: f"{v:.2f}%") if len(r["tendencia"]) > 1 else ""}
{_barras("Bajas por motivo", d['motivos'], "#e5484d")}
{_barras("Intervenciones por resultado", d['resultados'], "#1f7aec")}
{_barras("Intervenciones por canal", d['canales'], "#8e6cf0")}
{_barras("Bajas por mes", d['meses'], "#f5a623")}
{sec("Actividad en la app (últimas 24 h)")}<tr><td style="padding:0 24px"><table width="100%" cellpadding="0" cellspacing="0">{act}</table></td></tr>
{sec("Contratos activos a vigilar")}<tr><td style="padding:0 24px"><table width="100%" cellpadding="0" cellspacing="0">{vig}</table></td></tr>
<tr><td align="center" style="padding:22px 24px 0"><a href="{base}/dashboard" style="background:#1f7aec;color:#fff;font:700 14px Arial;padding:12px 22px;border-radius:8px;text-decoration:none;display:inline-block">Abrir dashboard en vivo</a></td></tr>
<tr><td style="padding:12px 24px 0;font:12px Arial;color:#667;text-align:center">Con este correo va adjunto <b>reporte-interactivo.html</b>: ábrelo en tu navegador y pasa el mouse sobre los gráficos.</td></tr>
<tr><td style="padding:24px;font:12px Arial;color:#889;text-align:center">Reporte automático · Retención de clientes G1<br>Datos en vivo desde Azure SQL</td></tr>
</table></body></html>"""


def adjunto_html(r):
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor", "chart.umd.js")
    try:
        js = open(p, encoding="utf-8").read()
    except OSError:
        js = None
    return render_template("reporte_adjunto.html", r=r, chartjs=js, resumen=resumen_texto(r))


def enviar_correo(asunto, html, para, texto="", adjuntos=()):
    usr, clave = os.environ.get("SMTP_USER"), os.environ.get("SMTP_PASSWORD")
    if not usr or not clave: raise RuntimeError("Falta configurar SMTP_USER y SMTP_PASSWORD")
    m = EmailMessage()
    m["Subject"] = asunto; m["From"] = f"Retención G1 <{usr}>"; m["To"] = usr; m["Bcc"] = ", ".join(para)
    m.set_content(texto or "Abre este mensaje en un lector de correo que muestre HTML.")
    m.add_alternative(html, subtype="html")
    for nombre, data in adjuntos:
        m.add_attachment(data, maintype="text", subtype="html", filename=nombre)
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ssl.create_default_context(), timeout=30) as srv:
        srv.login(usr, clave); srv.send_message(m)


def destinatarios(solo_admin=False):
    q = f"SELECT correo FROM {SCHEMA}.APP_USUARIOS WHERE activo=1 AND correo IS NOT NULL AND LTRIM(RTRIM(correo))<>''" + (" AND rol='administrador'" if solo_admin else "")
    return sorted({x["correo"].strip() for x in run(q)})


def enviar_reporte():
    para = destinatarios()
    if not para: raise RuntimeError("No hay usuarios activos con correo")
    r = datos_reporte(); k = r["k"]
    texto = (f"Reporte diario de retención {r['hoy']:%d/%m/%Y}. {resumen_texto(r)} Clientes: {k['clientes']} | Activos: {k['activos']} | "
             f"Cancelados: {k['cancelados']} | Tasa de cancelación: {k['tasa']}% | Intervenciones: {k['intervenciones']}")
    enviar_correo(f"📡 Reporte diario de retención · {r['hoy']:%d/%m/%Y}", correo_html(r, base_url()), para, texto,
                  [(f"reporte-interactivo-G1-{r['hoy']:%Y-%m-%d}.html", adjunto_html(r).encode("utf-8"))])
    guardar_snapshot(k, r["hoy"])
    return para


@app.route("/reportes/vista")
def reporte_vista():
    requiere("administrador", "supervisor")
    return correo_html(datos_reporte(), base_url())


@app.route("/reportes/vista-interactiva")
def reporte_vista_interactiva():
    requiere("administrador", "supervisor")
    return adjunto_html(datos_reporte())


# ---------------- Acceso de invitado (con aprobación) ----------------
def avisar_admins(nombre, correo, motivo):
    para = destinatarios(solo_admin=True)
    if not para: return
    e = _html.escape
    html = (f'<div style="font:15px Arial;max-width:520px;margin:auto"><h2 style="color:#0b3d6b">🔔 Solicitud de acceso como invitado</h2>'
            f'<p><b>{e(nombre)}</b> ({e(correo)}) quiere ver el dashboard del Grupo 1.</p>'
            f'<p>Motivo: {e(motivo or "no indicado")}</p>'
            f'<p><a href="{base_url()}/solicitudes" style="background:#1f7aec;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none;display:inline-block;font-weight:bold">Revisar y aprobar</a></p>'
            f'<p style="color:#667;font-size:13px">Debes iniciar sesión como administrador para aprobar. La solicitud vence en {VALIDEZ_SOLICITUD // 60} minutos. '
            f'Si no reconoces a esta persona, ignora este mensaje o recházala.</p></div>')
    enviar_correo(f"🔔 Solicitud de acceso al dashboard G1: {nombre}", html, para, f"{nombre} ({correo}) pide acceso de invitado. Revisa: {base_url()}/solicitudes")


@app.route("/invitado", methods=["GET", "POST"])
def invitado():
    if request.method == "POST":
        nombre = (request.form.get("nombre") or "").strip(); correo = (request.form.get("correo") or "").strip().lower()
        motivo = (request.form.get("motivo") or "").strip()[:300]
        if not (2 <= len(nombre) <= 100) or len(correo) > 150 or not EMAIL_RE.match(correo):
            flash("Escribe tu nombre completo y un correo válido", "err")
        elif (run("SELECT COUNT(*) AS n FROM G1.APP_SOLICITUDES WHERE creado > DATEADD(hour,-1,SYSUTCDATETIME())")[0]["n"] >= 20
              or run("SELECT COUNT(*) AS n FROM G1.APP_SOLICITUDES WHERE correo=? AND estado='pendiente' AND creado > DATEADD(minute,-30,SYSUTCDATETIME())", [correo])[0]["n"]):
            flash("Ya hay una solicitud en curso o hay demasiadas solicitudes. Intenta de nuevo en unos minutos.", "err")
        else:
            tok = secrets.token_hex(32)
            r = run("INSERT INTO G1.APP_SOLICITUDES (nombre,correo,motivo,token) OUTPUT INSERTED.solicitud_id AS id VALUES (?,?,?,?)", [nombre, correo, motivo or None, tok])
            session["sol"], session["sol_t"] = r[0]["id"], tok
            try:
                avisar_admins(nombre, correo, motivo)
            except Exception:
                pass
            return redirect(url_for("invitado_espera"))
    return render_template("invitado.html")


def _solicitud_sesion():
    if not session.get("sol"): return None
    r = run("SELECT solicitud_id,nombre,estado,token,DATEDIFF(second,creado,SYSUTCDATETIME()) AS edad, "
            "DATEDIFF(second,resuelto,SYSUTCDATETIME()) AS desde_res FROM G1.APP_SOLICITUDES WHERE solicitud_id=?", [session["sol"]])
    if not r or not secrets.compare_digest(str(r[0]["token"]).strip(), str(session.get("sol_t", ""))): return None
    return r[0]


@app.route("/invitado/espera")
def invitado_espera():
    if not session.get("sol"): return redirect(url_for("invitado"))
    return render_template("invitado_espera.html")


@app.route("/invitado/estado")
def invitado_estado():
    s_ = _solicitud_sesion()
    if not s_: return {"estado": "invalida"}
    est = s_["estado"]
    if est == "pendiente" and s_["edad"] > VALIDEZ_SOLICITUD: est = "expirada"
    return {"estado": est}


@app.route("/invitado/entrar")
def invitado_entrar():
    s_ = _solicitud_sesion()
    if not s_ or s_["estado"] != "aprobada" or (s_["desde_res"] or 0) > 900:
        flash("No se pudo validar tu acceso. Solicita uno nuevo.", "err"); return redirect(url_for("invitado"))
    run("UPDATE G1.APP_SOLICITUDES SET estado='usada' WHERE solicitud_id=? AND estado='aprobada'", [s_["solicitud_id"]], fetch=False)
    session.clear(); session.update(u=f"invitado-{s_['solicitud_id']}", nombre=s_["nombre"], rol="invitado", exp=time.time() + DURACION_INVITADO, dc=False); csrf()
    return redirect(url_for("dashboard"))


@app.route("/solicitudes")
def solicitudes():
    requiere("administrador")
    rows = run("SELECT TOP 50 solicitud_id,nombre,correo,motivo,estado,creado,DATEDIFF(second,creado,SYSUTCDATETIME()) AS edad "
               "FROM G1.APP_SOLICITUDES ORDER BY solicitud_id DESC")
    for x in rows:
        x["hora"] = (x["creado"] - datetime.timedelta(hours=5)).strftime("%d/%m %H:%M")
        x["vencida"] = x["estado"] == "pendiente" and x["edad"] > VALIDEZ_SOLICITUD
    return render_template("solicitudes.html", rows=rows, validez=VALIDEZ_SOLICITUD // 60)


@app.post("/solicitudes/<int:id>/<accion>")
def solicitud_resolver(id, accion):
    requiere("administrador")
    if accion not in ("aprobar", "rechazar"): abort(404)
    r = run("SELECT estado, DATEDIFF(second,creado,SYSUTCDATETIME()) AS edad FROM G1.APP_SOLICITUDES WHERE solicitud_id=?", [id])
    if not r: abort(404)
    if r[0]["estado"] != "pendiente": flash("Esta solicitud ya fue resuelta.", "err")
    elif accion == "aprobar" and r[0]["edad"] > VALIDEZ_SOLICITUD: flash("Esta solicitud venció. Pide a la persona que envíe otra.", "err")
    else:
        run("UPDATE G1.APP_SOLICITUDES SET estado=?, resuelto=SYSUTCDATETIME(), resuelto_por=? WHERE solicitud_id=? AND estado='pendiente'",
            ["aprobada" if accion == "aprobar" else "rechazada", session["u"], id], fetch=False)
        flash("Aprobada: la persona entrará en unos segundos." if accion == "aprobar" else "Solicitud rechazada.", "ok")
    return redirect(url_for("solicitudes"))


@app.route("/reportes/enviar-ahora", methods=["POST"])
def reporte_enviar_ahora():
    requiere("administrador")
    try:
        n = len(enviar_reporte()); flash(f"Reporte enviado a {n} correo(s).", "ok")
    except Exception as ex:
        flash(f"No se pudo enviar: {ex}", "err")
    return redirect(url_for("dashboard"))


@app.route("/reportes/enviar", methods=["POST"])
def reporte_enviar_token():
    tok = os.environ.get("REPORT_TOKEN")
    if not tok or not secrets.compare_digest(request.headers.get("X-Report-Token", ""), tok): abort(403)
    try:
        return {"ok": True, "enviados": len(enviar_reporte())}
    except Exception as ex:
        return {"ok": False, "error": str(ex)}, 500


@app.route("/<ent>")
def lista(ent):
    e = ENT.get(ent) or abort(404)
    if not puede("ver", ent): abort(403)
    q = request.args.get("q", "").strip(); pg = max(int(request.args.get("p", 1) or 1), 1)
    sel, joins = [f"t.{e['pk']}"], []
    for i, c in enumerate(e["campos"]):
        if c.get("src"):
            tb, idc, lb = c["src"]
            joins.append(f"LEFT JOIN {SCHEMA}.{tb} j{i} ON j{i}.{idc}=t.{c['n']}"); sel.append(f"j{i}.{lb} AS {c['n']}")
        else:
            sel.append(f"t.{c['n']}")
    sel += [f"{x[2]} AS {x[0]}" for x in e["extra"]]
    where, params = "", []
    if q:
        where = "WHERE " + " OR ".join(f"{b} LIKE ?" for b in e["buscar"]); params = [f"%{q}%"] * len(e["buscar"])
    T = f"{SCHEMA}.{e['tabla']} t"
    total = run(f"SELECT COUNT(*) AS n FROM {T} {where}", params)[0]["n"]
    rows = run(f"SELECT {','.join(sel)} FROM {T} {' '.join(joins)} {where} ORDER BY t.{e['pk']} DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
               params + [(pg - 1) * PAGE, PAGE])
    return render_template("lista.html", e=e, ent=ent, rows=rows, q=q, pg=pg, pages=max(math.ceil(total / PAGE), 1), total=total, ed=puede("editar", ent), el=puede("eliminar", ent))


@app.route("/<ent>/nuevo", methods=["GET", "POST"])
@app.route("/<ent>/<int:id>/editar", methods=["GET", "POST"])
def form(ent, id=None):
    e = ENT.get(ent) or abort(404)
    if not puede("editar", ent): abort(403)
    datos = {}
    if request.method == "POST":
        v, errs = leer(e, request.form, id)
        if not errs:
            try:
                guardar(e, v, id); log_act("editó" if id else "creó", ent, id); flash("Guardado correctamente", "ok"); return redirect(url_for("lista", ent=ent))
            except pyodbc.IntegrityError:
                errs.append("Revisa los datos: algún código indicado (cliente, contrato, etc.) no existe.")
        for m in errs: flash(m, "err")
        datos = request.form.to_dict()
    elif id:
        r = run(f"SELECT * FROM {SCHEMA}.{e['tabla']} WHERE {e['pk']}=?", [id])
        if not r: abort(404)
        datos = r[0]
    else:
        for c in e["campos"]:
            if c["t"] == "date" and c["req"]: datos[c["n"]] = datetime.date.today().isoformat()
            if c["t"] == "time": datos[c["n"]] = datetime.datetime.now().strftime("%H:%M")
    return render_template("form.html", e=e, ent=ent, id=id, datos=datos, opts={c["n"]: opciones(c) for c in e["campos"] if c["t"] == "sel"})


@app.post("/<ent>/<int:id>/eliminar")
def eliminar(ent, id):
    e = ENT.get(ent) or abort(404)
    if not puede("eliminar", ent): abort(403)
    try:
        run(f"DELETE FROM {SCHEMA}.{e['tabla']} WHERE {e['pk']}=?", [id], fetch=False); log_act("eliminó", ent, id); flash("Registro eliminado", "ok")
    except pyodbc.IntegrityError:
        flash("No se puede eliminar: tiene registros relacionados.", "err")
    return redirect(url_for("lista", ent=ent))


if __name__ == "__main__":
    app.run(debug=False)
