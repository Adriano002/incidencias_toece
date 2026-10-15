# app_incidencias.py
# Sistema de Incidencias - monolito
import base64
import hashlib
import logging
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

import pandas as pd
import qrcode
import streamlit as st
from qr_scanner_component import qr_scanner

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas as pdfcanvas

# ── Config ────────────────────────────────────────────────────────────
LOG_DIR = Path("logs"); LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler(LOG_DIR / "incidencias.log", encoding="utf-8"),
              logging.StreamHandler()])
log = logging.getLogger("incidencias")

DB_PATH = "incidencias.db"
PBK_ITER = 260_000
PBK_ALG = "sha256"
MAX_INTENTOS = 3
MIN_BLOQUEO = 10

TIPOS_INCIDENCIA = ["Leve", "Grave", "Muy grave"]
CATEGORIAS = ["Conducta", "Academico", "Salud", "Tardanza recurrente",
              "Falta de respeto", "Daño a propiedad", "Otro"]
ESTADOS = ["Abierta", "En proceso", "Resuelta", "Archivada"]

# ── Helpers ───────────────────────────────────────────────────────────
def ahora():
    return datetime.now(timezone.utc) - timedelta(hours=5)

def hoy_str():
    return ahora().strftime("%Y-%m-%d")

def hora_str():
    return ahora().strftime("%H:%M:%S")

def hora_corta():
    return ahora().strftime("%H:%M")

def timestamp_str():
    return ahora().strftime("%Y-%m-%d %H:%M:%S")

def mask_dni(dni):
    d = str(dni or "").strip()
    if len(d) < 4:
        return "****"
    return d[:4] + "*" * (len(d) - 4)

# ── DB ────────────────────────────────────────────────────────────────
@st.cache_resource
def _conn():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con

def conn():
    return _conn()

def leer_df(q, params=None):
    con = conn()
    return pd.read_sql_query(q, con, params=params or [])

def ejecutar(q, params=None):
    con = conn()
    cur = con.execute(q, params or [])
    con.commit()
    return cur

def escribir(q, params=None):
    ejecutar(q, params)

def aplicar_schema():
    con = conn()
    cur = con.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        rol TEXT NOT NULL,
        nombres TEXT NOT NULL,
        activo INTEGER DEFAULT 1,
        intentos_fallidos INTEGER DEFAULT 0,
        bloqueado_hasta TEXT,
        ultimo_login TEXT
    );

    CREATE TABLE IF NOT EXISTS alumnos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dni TEXT UNIQUE,
        nombres TEXT NOT NULL,
        apellido_paterno TEXT NOT NULL,
        apellido_materno TEXT,
        grado TEXT,
        seccion TEXT,
        turno TEXT,
        nombre_apoderado TEXT,
        telefono_apoderado TEXT,
        direccion TEXT,
        fecha_nacimiento TEXT,
        email_apoderado TEXT,
        activo INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS incidencias (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alumno_id INTEGER NOT NULL,
        fecha TEXT NOT NULL,
        hora TEXT NOT NULL,
        tipo TEXT NOT NULL,
        categoria TEXT,
        descripcion TEXT NOT NULL,
        reportado_por TEXT NOT NULL,
        estado TEXT DEFAULT 'Abierta',
        requiere_acta INTEGER DEFAULT 0,
        tipo_acta TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (alumno_id) REFERENCES alumnos(id)
    );

    CREATE TABLE IF NOT EXISTS actas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incidencia_id INTEGER NOT NULL,
        tipo TEXT NOT NULL,
        firmante_nombre TEXT,
        firma_base64 TEXT,
        firmado_en TEXT NOT NULL,
        observaciones TEXT,
        firma_alumno_base64 TEXT,
        firma_apoderado_base64 TEXT,
        nombre_alumno TEXT,
        nombre_apoderado TEXT,
        pdf_base64 TEXT,
        FOREIGN KEY (incidencia_id) REFERENCES incidencias(id)
    );

    CREATE TABLE IF NOT EXISTS auditoria (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario TEXT,
        accion TEXT,
        fecha TEXT,
        tabla_afectada TEXT,
        registro_id INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_inc_alumno ON incidencias(alumno_id);
    CREATE INDEX IF NOT EXISTS idx_inc_fecha ON incidencias(fecha);
    CREATE INDEX IF NOT EXISTS idx_actas_inc ON actas(incidencia_id);
    """)
    con.commit()

def _seed():
    con = conn()
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) AS n FROM usuarios")
    if cur.fetchone()["n"] == 0:
        pwd = secrets.token_urlsafe(9)
        cur.execute("INSERT INTO usuarios(usuario,password,rol,nombres) "
                    "VALUES(?,?,?,?)",
                    ("admin", hashear_password(pwd), "Admin", "Administrador"))
        con.commit()
        log.warning("admin creado, pass temporal: %s", pwd)

@st.cache_resource
def inicializar():
    aplicar_schema()
    _seed()
    return True

# ── Seguridad ─────────────────────────────────────────────────────────
def hashear_password(p):
    salt = secrets.token_bytes(16)
    d = hashlib.pbkdf2_hmac(PBK_ALG, p.encode("utf-8"), salt, PBK_ITER)
    return f"pbkdf2_{PBK_ALG}${PBK_ITER}${salt.hex()}${d.hex()}"

def verificar_password(p, h):
    if h.startswith("pbkdf2_"):
        try:
            _, it, salt_hex, hash_hex = h.split("$")
            d = hashlib.pbkdf2_hmac(PBK_ALG, p.encode("utf-8"),
                                     bytes.fromhex(salt_hex), int(it))
            return secrets.compare_digest(d.hex(), hash_hex)
        except (ValueError, TypeError):
            return False
    return secrets.compare_digest(
        hashlib.sha256(p.encode()).hexdigest(), h)

def _bloqueado(u):
    if not u.get("bloqueado_hasta"):
        return False
    try:
        bh = datetime.strptime(u["bloqueado_hasta"], "%Y-%m-%d %H:%M:%S")
        return ahora().replace(tzinfo=None) < bh
    except (ValueError, TypeError):
        return False

def autenticar(usuario, password):
    usuario = (usuario or "").strip().lower()
    con = conn()
    cur = con.execute("SELECT * FROM usuarios WHERE LOWER(usuario)=? AND activo=1",
                      (usuario,))
    f = cur.fetchone()
    if not f:
        return None, "Usuario no encontrado o inactivo"
    u = dict(f)
    if _bloqueado(u):
        bh = datetime.strptime(u["bloqueado_hasta"], "%Y-%m-%d %H:%M:%S")
        min_rest = int((bh - ahora().replace(tzinfo=None)).total_seconds() / 60) + 1
        return None, f"Cuenta bloqueada. Intenta en {min_rest} min"
    if not verificar_password(password, u["password"]):
        it = (u.get("intentos_fallidos") or 0) + 1
        if it >= MAX_INTENTOS:
            bh = (ahora() + timedelta(minutes=MIN_BLOQUEO)).strftime("%Y-%m-%d %H:%M:%S")
            con.execute("UPDATE usuarios SET intentos_fallidos=0,bloqueado_hasta=? "
                        "WHERE id=?", (bh, u["id"]))
            con.commit()
            return None, f"Cuenta bloqueada por {MIN_BLOQUEO} min"
        con.execute("UPDATE usuarios SET intentos_fallidos=? WHERE id=?",
                    (it, u["id"]))
        con.commit()
        return None, f"Credenciales incorrectas. Quedan {MAX_INTENTOS-it} intento(s)"
    con.execute("UPDATE usuarios SET intentos_fallidos=0,bloqueado_hasta=NULL,"
                "ultimo_login=? WHERE id=?",
                (timestamp_str(), u["id"]))
    con.commit()
    u["ultimo_login"] = timestamp_str()
    return u, ""

def auditar(usuario, accion, tb=None, rid=None):
    try:
        escribir("INSERT INTO auditoria(usuario,accion,fecha,tabla_afectada,"
                 "registro_id) VALUES(?,?,?,?,?)",
                 (usuario, accion, timestamp_str(), tb, rid))
    except Exception as e:
        log.warning("audit: %s", e)

def pedir_password_critica(clave, texto_boton="Confirmar",
                            texto_input="Contraseña de Admin o Direccion"):
    pwd = st.text_input(texto_input, type="password", key="pwd_crit_" + clave)
    conf = st.checkbox("Confirmo esta accion", key="conf_crit_" + clave)
    if st.button(texto_boton, type="primary", key="btn_crit_" + clave,
                 disabled=not conf):
        if not pwd:
            st.error("Ingresa la contraseña."); return False
        con = conn()
        cur = con.execute("SELECT password FROM usuarios "
                          "WHERE rol IN ('Admin','Direccion') AND activo=1")
        if not any(verificar_password(pwd, r["password"]) for r in cur.fetchall()):
            st.error("Contraseña incorrecta."); return False
        return True
    return False

# ── Helpers grado/seccion ─────────────────────────────────────────────
def obtener_grados():
    df = leer_df("""SELECT DISTINCT grado FROM alumnos
                    WHERE activo=1 AND grado IS NOT NULL AND grado!=''
                    ORDER BY grado""")
    return [""] + df["grado"].tolist()

def obtener_secciones(grado=""):
    if grado:
        df = leer_df("""SELECT DISTINCT seccion FROM alumnos
                        WHERE activo=1 AND grado=? AND seccion IS NOT NULL
                        AND seccion!='' ORDER BY seccion""", (grado,))
    else:
        df = leer_df("""SELECT DISTINCT seccion FROM alumnos
                        WHERE activo=1 AND seccion IS NOT NULL
                        AND seccion!='' ORDER BY seccion""")
    return [""] + df["seccion"].tolist()

# ── Scanner QR ────────────────────────────────────────────────────────
def buscar_alumno_por_dni(dni):
    con = conn()
    cur = con.execute("SELECT * FROM alumnos WHERE dni=? AND activo=1", (dni,))
    f = cur.fetchone()
    return dict(f) if f else None

def componente_escaner(key):
    mount_id = st.session_state.get(f"_qr_mount_{key}", 0)
    result = qr_scanner(key=f"qr_{key}_{mount_id}", on_scan=lambda: None)
    if result is not None and getattr(result, "qr_dni", None):
        return str(result.qr_dni).strip()
    return None

def escaner_widget(key="escaner"):
    dni = componente_escaner(key)
    if dni:
        procesado_key = f"_qr_procesado_{key}"
        ult = st.session_state.get(procesado_key, {})
        if ult.get("dni") == dni:
            return None
        st.session_state[procesado_key] = {"dni": dni, "ts": time.time()}
        st.session_state[f"_qr_mount_{key}"] = \
            st.session_state.get(f"_qr_mount_{key}", 0) + 1
        al = buscar_alumno_por_dni(dni)
        if al:
            return al
        else:
            st.error(f"No hay alumno con DNI {mask_dni(dni)}")
    return None

def limpiar_escaner(key):
    st.session_state.pop(f"_qr_procesado_{key}", None)
    st.session_state.pop(f"_ult_qr_{key}", None)

# ── Vistas: login, cuenta ─────────────────────────────────────────────
def vista_login():
    st.title("incidencias")
    st.caption("Sistema de Incidencias Escolares")
    _, centro, _ = st.columns([1, 1, 1])
    with centro:
        with st.form("login"):
            usuario = st.text_input("Usuario", placeholder="tu usuario")
            password = st.text_input("Contraseña", type="password",
                                     placeholder="tu contraseña")
            enviado = st.form_submit_button("Ingresar", type="primary",
                                            use_container_width=True)
            if enviado:
                datos, err = autenticar(usuario, password)
                if datos:
                    st.session_state["user"] = datos
                    auditar(datos["usuario"], "Login")
                    st.rerun()
                else:
                    st.error(err or "Credenciales incorrectas")

def cerrar_sesion():
    u = st.session_state.get("user")
    if u:
        auditar(u["usuario"], "Logout")
    for k in list(st.session_state.keys()):
        del st.session_state[k]

def vista_mi_cuenta():
    st.title("Mi cuenta")
    u = st.session_state["user"]
    st.write(f"**Nombre:** {u['nombres']}")
    st.write(f"**Usuario:** {u['usuario']}")
    st.write(f"**Rol:** {u['rol']}")
    st.write(f"**Ultimo login:** {u.get('ultimo_login') or 'Nunca'}")
    st.markdown("---")
    st.subheader("Cambiar contraseña")
    with st.form("cambiar_pwd"):
        actual = st.text_input("Contraseña actual", type="password")
        nueva = st.text_input("Nueva contraseña", type="password")
        confirmar = st.text_input("Confirmar nueva", type="password")
        if st.form_submit_button("Cambiar", type="primary"):
            if not verificar_password(actual, u["password"]):
                st.error("Contraseña actual incorrecta.")
            elif len(nueva) < 6:
                st.error("Minimo 6 caracteres.")
            elif nueva != confirmar:
                st.error("No coinciden.")
            else:
                h = hashear_password(nueva)
                escribir("UPDATE usuarios SET password=? WHERE id=?", (h, u["id"]))
                st.session_state["user"]["password"] = h
                auditar(u["usuario"], "Cambio su contraseña")
                st.success("Contraseña actualizada.")

# ── Menú y router ─────────────────────────────────────────────────────
def obtener_opciones_por_rol(u):
    rol = u["rol"]
    if rol == "Admin":
        return ["Escaner QR", "Incidencias", "Alumnos", "Actas",
                "Reportes", "Usuarios", "Auditoria", "Mi cuenta"]
    if rol == "Direccion":
        return ["Escaner QR", "Incidencias", "Alumnos", "Actas",
                "Reportes", "Mi cuenta"]
    if rol == "Auxiliar":
        return ["Escaner QR", "Incidencias", "Alumnos",
                "Reportes", "Mi cuenta"]
    return []

def menu_lateral():
    u = st.session_state["user"]
    rol = u["rol"]
    opciones = obtener_opciones_por_rol(u)
    with st.sidebar:
        st.write(f"**{u['nombres']}**")
        st.caption(f"Rol: {rol}")
        if "menu" not in st.session_state or st.session_state["menu"] not in opciones:
            st.session_state["menu"] = opciones[0]
        op = st.radio("Menu", opciones, key="menu", label_visibility="collapsed")
        st.markdown("---")
        if st.button("Cerrar sesion", use_container_width=True):
            cerrar_sesion(); st.rerun()
    return op

# ── Componente FIRMA DIGITAL ──────────────────────────────────────────
_FIRMA_HTML = """
<div id="firma-wrapper">
    <canvas id="firma-canvas" width="600" height="220"></canvas>
    <div id="firma-botones">
        <button id="btn-limpiar" type="button">Limpiar</button>
    </div>
    <div id="firma-hint">Firma con el mouse o con el dedo</div>
</div>
"""

_FIRMA_CSS = """
#firma-wrapper{max-width:620px;margin:0 auto;background:#FAFAFA;
    border:2px dashed #E65100;border-radius:10px;padding:10px;}
#firma-canvas{width:100%;background:#FFF;border-radius:6px;
    cursor:crosshair;touch-action:none;border:1px solid #DDD;}
#firma-botones{display:flex;justify-content:center;margin-top:8px;}
#btn-limpiar{background:#E65100;color:#FFF;border:none;border-radius:6px;
    padding:8px 20px;font-weight:700;cursor:pointer;font-size:14px;}
#btn-limpiar:hover{background:#BF360C;}
#firma-hint{text-align:center;font-size:12px;color:#888;margin-top:6px;}
"""

_FIRMA_JS = """
export default function(component){
    const { setTriggerValue } = component;
    const canvas = document.getElementById('firma-canvas');
    const ctx = canvas.getContext('2d');
    let dibujando = false;
    let huboTrazo = false;
    ctx.lineWidth = 2.5;
    ctx.lineCap = 'round';
    ctx.strokeStyle = '#111';

    function pos(e){
        const r = canvas.getBoundingClientRect();
        const cx = (e.touches ? e.touches[0].clientX : e.clientX) - r.left;
        const cy = (e.touches ? e.touches[0].clientY : e.clientY) - r.top;
        return [cx * (canvas.width / r.width), cy * (canvas.height / r.height)];
    }
    function start(e){ e.preventDefault(); dibujando = true; const [x,y]=pos(e);
        ctx.beginPath(); ctx.moveTo(x,y); }
    function move(e){ if(!dibujando) return; e.preventDefault(); const [x,y]=pos(e);
        ctx.lineTo(x,y); ctx.stroke(); huboTrazo = true; }
    function end(e){ if(!dibujando) return; e.preventDefault(); dibujando = false;
        if(huboTrazo) setTriggerValue("firma_data", canvas.toDataURL('image/png')); }

    canvas.addEventListener('mousedown', start);
    canvas.addEventListener('mousemove', move);
    canvas.addEventListener('mouseup', end);
    canvas.addEventListener('mouseleave', end);
    canvas.addEventListener('touchstart', start, {passive:false});
    canvas.addEventListener('touchmove', move, {passive:false});
    canvas.addEventListener('touchend', end);

    document.getElementById('btn-limpiar').addEventListener('click', () => {
        ctx.clearRect(0,0,canvas.width,canvas.height);
        huboTrazo = false;
        setTriggerValue("firma_data", "");
    });
}
"""

@st.cache_resource
def _firma_component(name):
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    return st.components.v2.component(
        name=f"firma_canvas_{safe}",
        isolate_styles=False,
        html=_FIRMA_HTML,
        css=_FIRMA_CSS,
        js=_FIRMA_JS,
    )

def firma_widget(key="firma"):
    comp = _firma_component(key)
    result = comp(key=key)
    if result is not None and getattr(result, "firma_data", None):
        st.session_state[f"_firma_actual_{key}"] = result.firma_data
    return result

def firma_guardada(key):
    return st.session_state.get(f"_firma_actual_{key}")

# ── Alumnos ───────────────────────────────────────────────────────────
def buscar_alumnos(texto="", grado="", seccion="", dni="", limite=300):
    q = """SELECT id,dni,nombres,apellido_paterno,apellido_materno,
           grado,seccion,turno,nombre_apoderado,telefono_apoderado,
           direccion,fecha_nacimiento,email_apoderado
           FROM alumnos WHERE activo=1"""
    p = []
    if texto:
        for w in [x.strip() for x in texto.split() if x.strip()]:
            q += (" AND (nombres LIKE ? OR apellido_paterno LIKE ? "
                  "OR apellido_materno LIKE ?)")
            pat = f"%{w}%"
            p += [pat, pat, pat]
    if dni:
        q += " AND dni LIKE ?"; p.append(f"%{dni}%")
    if grado:
        q += " AND grado = ?"; p.append(grado)
    if seccion:
        q += " AND seccion = ?"; p.append(seccion)
    q += " ORDER BY apellido_paterno LIMIT ?"; p.append(limite)
    return leer_df(q, p)

def crear_alumno(dni, nombres, ap, am, grado, seccion, turno,
                 apo_n, apo_t, direccion, fecha_nac, email_apo, usuario):
    try:
        escribir("""INSERT INTO alumnos(dni,nombres,apellido_paterno,
                    apellido_materno,grado,seccion,turno,
                    nombre_apoderado,telefono_apoderado,direccion,
                    fecha_nacimiento,email_apoderado)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                 (dni or None, nombres, ap, am or None, grado, seccion, turno,
                  apo_n or None, apo_t or None, direccion or None,
                  fecha_nac or None, email_apo or None))
        auditar(usuario["usuario"], f"Creo alumno DNI {mask_dni(dni)}", "alumnos")
        return True, f"Alumno {nombres} creado."
    except Exception as e:
        if "unique" in str(e).lower():
            return False, f"Ya existe un alumno con DNI {mask_dni(dni)}"
        log.error("crear_alumno: %s", e)
        return False, "Error al crear."

def editar_alumno(idal, grado, seccion, turno, apo_n, apo_t,
                  direccion, fecha_nac, email_apo, usuario):
    escribir("""UPDATE alumnos SET grado=?,seccion=?,turno=?,
                nombre_apoderado=?,telefono_apoderado=?,direccion=?,
                fecha_nacimiento=?,email_apoderado=? WHERE id=?""",
             (grado, seccion, turno, apo_n or None, apo_t or None,
              direccion or None, fecha_nac or None, email_apo or None, idal))
    auditar(usuario["usuario"], f"Edito alumno id={idal}", "alumnos", idal)
    return True, "Alumno editado."

def retirar_alumno(idal, usuario):
    escribir("UPDATE alumnos SET activo=0 WHERE id=?", (idal,))
    auditar(usuario["usuario"], f"Desactivo alumno id={idal}", "alumnos", idal)
    return True, "Alumno desactivado."

def reactivar_alumno(idal, usuario):
    escribir("UPDATE alumnos SET activo=1 WHERE id=?", (idal,))
    auditar(usuario["usuario"], f"Reactivo alumno id={idal}", "alumnos", idal)
    return True, "Alumno reactivado."

# ── PDF ACTAS ─────────────────────────────────────────────────────────
def generar_pdf_acta(incidencia, alumno, acta_data):
    buf = BytesIO()
    c = pdfcanvas.Canvas(buf, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(2*cm, height - 2*cm, "ACTA DE INCIDENCIA")
    c.setFont("Helvetica", 10)
    c.drawString(2*cm, height - 2.7*cm,
                 f"Fecha de emision: {timestamp_str()}")

    y = height - 4*cm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y, "Datos del alumno")
    y -= 0.7*cm
    c.setFont("Helvetica", 11)
    nombre_al = (f"{alumno.get('apellido_paterno','')} "
                 f"{alumno.get('apellido_materno','') or ''}, "
                 f"{alumno.get('nombres','')}")
    c.drawString(2*cm, y, f"Nombre: {nombre_al}")
    y -= 0.6*cm
    c.drawString(2*cm, y, f"DNI: {alumno.get('dni','')}")
    y -= 0.6*cm
    c.drawString(2*cm, y, f"Grado y seccion: {alumno.get('grado','')} "
                          f"{alumno.get('seccion','')}")
    y -= 0.6*cm
    c.drawString(2*cm, y, f"Turno: {alumno.get('turno','') or '-'}")
    y -= 0.6*cm
    c.drawString(2*cm, y, f"Apoderado: {alumno.get('nombre_apoderado','') or '-'}")
    y -= 0.6*cm
    c.drawString(2*cm, y, f"Telefono apoderado: "
                          f"{alumno.get('telefono_apoderado','') or '-'}")

    y -= 1*cm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y, "Datos de la incidencia")
    y -= 0.7*cm
    c.setFont("Helvetica", 11)
    c.drawString(2*cm, y, f"Fecha: {incidencia.get('fecha','')} "
                          f"{incidencia.get('hora','')}")
    y -= 0.6*cm
    c.drawString(2*cm, y, f"Tipo: {incidencia.get('tipo','')}")
    y -= 0.6*cm
    c.drawString(2*cm, y, f"Categoria: {incidencia.get('categoria','') or '-'}")
    y -= 0.6*cm
    c.drawString(2*cm, y, f"Reportado por: {incidencia.get('reportado_por','')}")

    y -= 1*cm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y, "Descripcion de los hechos")
    y -= 0.7*cm
    c.setFont("Helvetica", 10)
    texto = incidencia.get("descripcion", "") or ""
    for linea in _wrap_text(texto, 90):
        c.drawString(2*cm, y, linea)
        y -= 0.5*cm
        if y < 6*cm:
            c.showPage()
            y = height - 2*cm
            c.setFont("Helvetica", 10)

    y -= 0.5*cm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y, "Observaciones / Acuerdos")
    y -= 0.7*cm
    c.setFont("Helvetica", 10)
    obs = acta_data.get("observaciones", "") or ""
    for linea in _wrap_text(obs, 90):
        c.drawString(2*cm, y, linea)
        y -= 0.5*cm
        if y < 6*cm:
            c.showPage()
            y = height - 2*cm
            c.setFont("Helvetica", 10)

    y -= 1.5*cm
    if y < 8*cm:
        c.showPage()
        y = height - 3*cm

    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y, "Firmas")
    y -= 1*cm

    firma_al = acta_data.get("firma_alumno_base64")
    if firma_al:
        try:
            img_bytes = base64.b64decode(firma_al.split(",")[-1])
            img = ImageReader(BytesIO(img_bytes))
            c.drawImage(img, 2*cm, y - 2.5*cm, width=6*cm, height=2.2*cm,
                        preserveAspectRatio=True, mask='auto')
        except Exception as e:
            log.warning("firma alumno pdf: %s", e)
    c.setFont("Helvetica", 10)
    c.drawString(2*cm, y - 3*cm, "____________________________")
    c.drawString(2*cm, y - 3.5*cm,
                 f"Alumno: {acta_data.get('nombre_alumno','') or nombre_al}")

    firma_apo = acta_data.get("firma_apoderado_base64")
    if firma_apo:
        try:
            img_bytes = base64.b64decode(firma_apo.split(",")[-1])
            img = ImageReader(BytesIO(img_bytes))
            c.drawImage(img, 10*cm, y - 2.5*cm, width=6*cm, height=2.2*cm,
                        preserveAspectRatio=True, mask='auto')
        except Exception as e:
            log.warning("firma apoderado pdf: %s", e)
    c.setFont("Helvetica", 10)
    c.drawString(10*cm, y - 3*cm, "____________________________")
    c.drawString(10*cm, y - 3.5*cm,
                 f"Apoderado: {acta_data.get('nombre_apoderado','') or alumno.get('nombre_apoderado','') or '-'}")

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.getvalue()

def _wrap_text(texto, ancho):
    palabras = str(texto).split()
    lineas = []
    actual = ""
    for p in palabras:
        if len(actual) + len(p) + 1 <= ancho:
            actual = (actual + " " + p).strip()
        else:
            if actual:
                lineas.append(actual)
            actual = p
    if actual:
        lineas.append(actual)
    return lineas or [""]

# ── ACTAS ─────────────────────────────────────────────────────────────
def crear_acta_doble(incidencia_id, firmante, firma_alumno, firma_apoderado,
                     obs, nombre_alumno, nombre_apoderado, usuario):
    con = conn()
    cur = con.execute("SELECT * FROM incidencias WHERE id=?", (incidencia_id,))
    inc = cur.fetchone()
    if not inc:
        return False, "Incidencia no encontrada."
    inc = dict(inc)
    cur = con.execute("SELECT * FROM alumnos WHERE id=?", (inc["alumno_id"],))
    al = dict(cur.fetchone())

    acta_data = {
        "tipo": "alumno_apoderado",
        "firmante_nombre": firmante,
        "observaciones": obs,
        "firma_alumno_base64": firma_alumno,
        "firma_apoderado_base64": firma_apoderado,
        "nombre_alumno": nombre_alumno,
        "nombre_apoderado": nombre_apoderado,
    }
    pdf_bytes = generar_pdf_acta(inc, al, acta_data)
    pdf_b64 = base64.b64encode(pdf_bytes).decode("utf-8")

    con.execute("""INSERT INTO actas(incidencia_id,tipo,firmante_nombre,
                    firma_base64,firmado_en,observaciones,
                    firma_alumno_base64,firma_apoderado_base64,
                    nombre_alumno,nombre_apoderado,pdf_base64)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (incidencia_id, "alumno_apoderado", firmante,
                 firma_apoderado or firma_alumno, timestamp_str(), obs or None,
                 firma_alumno, firma_apoderado, nombre_alumno, nombre_apoderado,
                 pdf_b64))
    con.commit()
    auditar(usuario["usuario"],
            f"Firmo acta (alumno+apoderado) incidencia id={incidencia_id}",
            "actas", incidencia_id)
    return True, "Acta firmada y PDF generado."

def actas_de_incidencia(inc_id):
    return leer_df("""SELECT id,tipo,firmante_nombre,firmado_en,
                      observaciones,nombre_alumno,nombre_apoderado,
                      pdf_base64
                      FROM actas
                      WHERE incidencia_id=? ORDER BY id""", (inc_id,))

def firma_de_acta(acta_id):
    con = conn()
    cur = con.execute("SELECT firma_alumno_base64, firma_apoderado_base64, "
                      "firma_base64 FROM actas WHERE id=?", (acta_id,))
    f = cur.fetchone()
    return dict(f) if f else {}

# ── VISTA ESCANER QR ──────────────────────────────────────────────────
def vista_escaner():
    st.title("Escáner QR")

    modo = st.radio(
        "Modo",
        ["Ver perfil", "Registrar incidencia"],
        horizontal=True,
        key="scan_modo",
    )

    st.markdown("---")

    key_scan = "scan_" + modo.lower().replace(" ", "_")
    al = escaner_widget(key_scan)
    if not al:
        return

    st.success(f"{al['nombres']} {al['apellido_paterno']} — "
               f"{al['grado'] or ''} {al['seccion'] or ''} — "
               f"DNI {mask_dni(al['dni'])}")

    st.markdown("---")

    if modo == "Ver perfil":
        _perfil_inline(al["id"], key_scan)
    else:
        _incidencia_inline(al, key_scan)


def _perfil_inline(idal, key_scan):
    al = _obtener_alumno(idal)
    if not al:
        st.warning("Alumno no encontrado."); return
    st.subheader("Perfil del alumno")
    st.write(f"**Nombre:** {al['apellido_paterno']} "
             f"{al['apellido_materno'] or ''}, {al['nombres']}")
    st.write(f"**DNI:** {mask_dni(al['dni'])}")
    st.write(f"**Grado/Seccion:** {al['grado'] or ''} {al['seccion'] or ''}")
    st.write(f"**Turno:** {al['turno'] or '-'}")
    st.write(f"**Apoderado:** {al.get('nombre_apoderado') or '-'}")
    st.write(f"**Telefono:** {al.get('telefono_apoderado') or '-'}")

    if st.button("Abrir perfil completo", type="primary",
                 key="scan_abrir_perfil"):
        st.session_state["alumno_perfil_id"] = idal
        limpiar_escaner(key_scan)
        st.rerun()


def _incidencia_inline(al, key_scan):
    st.subheader("Nueva incidencia")
    with st.form("form_inc_scan"):
        c1, c2 = st.columns(2)
        with c1:
            fecha = st.date_input("Fecha", value=ahora().date())
            tipo = st.selectbox("Tipo", TIPOS_INCIDENCIA)
        with c2:
            categoria = st.selectbox("Categoria", CATEGORIAS)
            reportado = st.text_input("Reportado por",
                                       value=st.session_state["user"]["nombres"])
        descripcion = st.text_area("Descripcion *")
        requiere_acta = st.checkbox("¿Requiere acta?")
        tipo_acta = None
        if requiere_acta:
            tipo_acta = st.radio("Tipo de acta",
                                 ["alumno", "apoderado", "alumno_apoderado"],
                                 horizontal=True)
        sub = st.form_submit_button("Registrar incidencia", type="primary")

    if sub:
        if not descripcion.strip():
            st.error("Descripcion obligatoria.")
        else:
            ok, msg = crear_incidencia(
                al["id"], fecha.strftime("%Y-%m-%d"), tipo, categoria,
                descripcion.strip(), reportado.strip(),
                requiere_acta, tipo_acta, st.session_state["user"])
            if ok:
                limpiar_escaner(key_scan)
                st.toast(msg)
                st.rerun()
            else:
                st.error(msg)

# ── VISTA ALUMNOS ─────────────────────────────────────────────────────
def vista_alumnos():
    st.title("Alumnos")
    pid = st.session_state.get("alumno_perfil_id")
    if pid:
        vista_perfil_alumno(pid); return
    tabs = st.tabs(["Buscar", "Ir al escaner", "Crear", "Importar Excel"])

    with tabs[0]:
        st.subheader("Buscar alumno")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            f_nombre = st.text_input("Nombre o apellido", key="al_f_nom")
        with c2:
            f_dni = st.text_input("DNI", key="al_f_dni")
        with c3:
            grados = obtener_grados()
            f_grado = st.selectbox("Grado", grados, key="al_f_grado")
        with c4:
            secciones = obtener_secciones(f_grado)
            f_seccion = st.selectbox("Seccion", secciones, key="al_f_sec")
        if st.button("Buscar", type="primary", key="al_buscar_btn"):
            st.session_state["_al_buscar"] = True
        if st.session_state.get("_al_buscar"):
            df = buscar_alumnos(f_nombre, f_grado, f_seccion, f_dni,
                                limite=500)
            st.write(f"{len(df)} resultados")
            if df.empty:
                st.info("Sin resultados.")
            else:
                for _, al in df.iterrows():
                    nombre = (al['apellido_paterno'] + " " +
                              (al['apellido_materno'] or "") + ", " + al['nombres'])
                    c1, c2 = st.columns([5, 1])
                    c1.write(f"**{nombre}** — {al['grado'] or ''} "
                             f"{al['seccion'] or ''} — DNI {mask_dni(al['dni'])}")
                    if c2.button("Ver perfil", key="ver_al_" + str(al['id'])):
                        st.session_state["alumno_perfil_id"] = al["id"]; st.rerun()

    with tabs[1]:
        st.subheader("Escanear carnet")
        st.info("El escaner esta en su propia seccion del menu lateral.")
        if st.button("Ir a Escaner QR", type="primary", key="ir_a_escaner"):
            st.session_state["menu"] = "Escaner QR"
            st.rerun()

    with tabs[2]:
        st.subheader("Crear alumno")
        c1, c2 = st.columns(2)
        with c1:
            dni = st.text_input("DNI * (8 digitos)", max_chars=8, key="nu_dni")
            nom = st.text_input("Nombres *", key="nu_nom")
            pat = st.text_input("Apellido Paterno *", key="nu_pat")
            mat = st.text_input("Apellido Materno", key="nu_mat")
        with c2:
            grado = st.text_input("Grado", key="nu_grado")
            seccion = st.text_input("Seccion", key="nu_sec")
            turno = st.selectbox("Turno", ["", "Mañana", "Tarde"], key="nu_tur")
            fecha_nac = st.date_input("Fecha de nacimiento", value=None,
                                       key="nu_fnac")
        c3, c4 = st.columns(2)
        with c3:
            apo = st.text_input("Apoderado", key="nu_apo")
            tel = st.text_input("Telefono apoderado", key="nu_tel")
        with c4:
            email_apo = st.text_input("Email apoderado", key="nu_email")
            direccion = st.text_input("Direccion", key="nu_dir")
        if st.button("Crear alumno", type="primary"):
            if not dni or not nom or not pat:
                st.error("Completa DNI, nombres y apellido paterno.")
            elif not re.fullmatch(r"\d{8}", dni.strip()):
                st.error("DNI invalido.")
            else:
                fn = fecha_nac.strftime("%Y-%m-%d") if fecha_nac else None
                ok, msg = crear_alumno(dni.strip(), nom.strip(), pat.strip(),
                                        mat.strip(), grado.strip(),
                                        seccion.strip(), turno,
                                        apo.strip(), tel.strip(),
                                        direccion.strip(), fn,
                                        email_apo.strip(),
                                        st.session_state["user"])
                if ok:
                    st.toast(msg); st.rerun()
                else:
                    st.error(msg)

    with tabs[3]:
        st.subheader("Importar alumnos desde Excel")
        st.caption("Columnas: DNI, Nombres, Apellido Paterno, Apellido Materno, "
                   "Grado, Seccion, Turno, Apoderado, Telefono.")
        arch = st.file_uploader("Sube el Excel", type=["xlsx", "xls"],
                                 key="al_imp")
        if arch:
            df = pd.read_excel(arch)
            st.write(f"{len(df)} filas detectadas.")
            cols = list(df.columns)
            with st.form("mapeo_al"):
                c1, c2 = st.columns(2)
                with c1:
                    m_dni = st.selectbox("DNI *", cols)
                    m_nom = st.selectbox("Nombres *", cols)
                    m_pat = st.selectbox("Apellido Paterno *", cols)
                    m_mat = st.selectbox("Apellido Materno", [""] + cols)
                with c2:
                    m_gra = st.selectbox("Grado", [""] + cols)
                    m_sec = st.selectbox("Seccion", [""] + cols)
                    m_tur = st.selectbox("Turno", [""] + cols)
                    m_apo = st.selectbox("Apoderado", [""] + cols)
                    m_tel = st.selectbox("Telefono", [""] + cols)
                validar = st.form_submit_button("Validar", type="primary")
            if validar:
                mapeo = {"dni": m_dni, "nombres": m_nom,
                         "apellido_paterno": m_pat,
                         "apellido_materno": m_mat, "grado": m_gra,
                         "seccion": m_sec, "turno": m_tur,
                         "apoderado_nombre": m_apo,
                         "apoderado_telefono": m_tel}
                val, errs, res = validar_importacion_alumnos(df, mapeo)
                st.session_state["_al_val"] = val
                st.session_state["_al_err"] = errs
                st.session_state["_al_res"] = res
            if "_al_res" in st.session_state:
                r = st.session_state["_al_res"]
                c1, c2, c3 = st.columns(3)
                c1.metric("Total", r["total"])
                c2.metric("Validas", r["validas"])
                c3.metric("Errores", r["errores"])
                if st.session_state["_al_err"]:
                    with st.expander("Errores"):
                        st.dataframe(pd.DataFrame(st.session_state["_al_err"]),
                                     use_container_width=True)
                if st.session_state["_al_val"]:
                    if pedir_password_critica("al_imp", "Importar validas"):
                        ins, reac, errs = insertar_alumnos_validos(
                            st.session_state["_al_val"])
                        st.toast(f"{ins} nuevos, {reac} actualizados.")
                        for k in ["_al_val", "_al_err", "_al_res"]:
                            st.session_state.pop(k, None)
                        st.rerun()

def validar_importacion_alumnos(df, mapeo):
    errs, val = [], []
    vistos = set()
    for idx, fila in df.iterrows():
        nf = idx + 2
        try:
            def _l(v):
                if v is None: return ""
                if isinstance(v, float):
                    if pd.isna(v): return ""
                    if v == int(v): return str(int(v))
                    return str(v)
                s = str(v).strip()
                if s.endswith(".0") and s[:-2].isdigit(): s = s[:-2]
                return "" if s.lower() == "nan" else s
            dni = _l(fila[mapeo["dni"]])
            nom = _l(fila[mapeo["nombres"]])
            ap = _l(fila[mapeo["apellido_paterno"]])
            am = _l(fila[mapeo["apellido_materno"]]) if mapeo.get("apellido_materno") else ""
            gr = _l(fila[mapeo["grado"]]) if mapeo.get("grado") else ""
            sec = _l(fila[mapeo["seccion"]]) if mapeo.get("seccion") else ""
            tur = _l(fila[mapeo["turno"]]) if mapeo.get("turno") else ""
            an = _l(fila[mapeo["apoderado_nombre"]]) if mapeo.get("apoderado_nombre") else ""
            at = _l(fila[mapeo["apoderado_telefono"]]) if mapeo.get("apoderado_telefono") else ""

            if not dni or not re.fullmatch(r"\d{8}", dni):
                errs.append({"fila": nf, "motivo": "DNI invalido"}); continue
            if dni in vistos:
                errs.append({"fila": nf, "motivo": f"DNI {mask_dni(dni)} duplicado"}); continue
            if not nom or not ap:
                errs.append({"fila": nf, "motivo": "Faltan nombres"}); continue
            vistos.add(dni)
            val.append({"dni": dni, "nombres": nom, "apellido_paterno": ap,
                        "apellido_materno": am, "grado": gr, "seccion": sec,
                        "turno": tur, "apoderado_nombre": an,
                        "apoderado_telefono": at})
        except Exception as e:
            errs.append({"fila": nf, "motivo": str(e)})
    return val, errs, {"total": len(df), "validas": len(val), "errores": len(errs)}

def insertar_alumnos_validos(val):
    ins = reac = 0; errs = []
    con = conn()
    for d in val:
        try:
            cur = con.execute("SELECT id FROM alumnos WHERE dni=?", (d["dni"],))
            ex = cur.fetchone()
            if ex:
                con.execute("""UPDATE alumnos SET nombres=?,apellido_paterno=?,
                               apellido_materno=?,grado=?,seccion=?,turno=?,
                               nombre_apoderado=?,telefono_apoderado=?,activo=1
                               WHERE id=?""",
                            (d["nombres"], d["apellido_paterno"],
                             d["apellido_materno"] or None, d["grado"], d["seccion"],
                             d["turno"], d["apoderado_nombre"] or None,
                             d["apoderado_telefono"] or None, ex["id"]))
                reac += 1
            else:
                con.execute("""INSERT INTO alumnos(dni,nombres,apellido_paterno,
                               apellido_materno,grado,seccion,turno,
                               nombre_apoderado,telefono_apoderado,activo)
                               VALUES(?,?,?,?,?,?,?,?,?,1)""",
                            (d["dni"], d["nombres"], d["apellido_paterno"],
                             d["apellido_materno"] or None, d["grado"], d["seccion"],
                             d["turno"], d["apoderado_nombre"] or None,
                             d["apoderado_telefono"] or None))
                ins += 1
        except Exception as e:
            errs.append(f"{mask_dni(d['dni'])}: {e}")
    con.commit()
    return ins, reac, errs

# ── VISTA ACTAS ───────────────────────────────────────────────────────
def vista_actas():
    st.title("Actas firmadas")
    df = leer_df("""
        SELECT a.id AS incidencia_id, a.fecha, a.tipo, a.categoria,
        al.apellido_paterno||' '||COALESCE(al.apellido_materno,'')||', '||al.nombres AS alumno,
        al.grado, al.seccion,
        (SELECT COUNT(*) FROM actas WHERE incidencia_id=a.id) AS n_actas
        FROM incidencias a JOIN alumnos al ON a.alumno_id=al.id
        WHERE a.requiere_acta=1
        ORDER BY a.fecha DESC LIMIT 200
    """)
    if df.empty:
        st.info("No hay incidencias con acta requerida.")
        return
    st.write(f"{len(df)} incidencias con acta.")
    for _, r in df.iterrows():
        with st.expander(f"{r['fecha']} - {r['alumno']} - "
                         f"{r['tipo']} ({r['n_actas']} acta(s))"):
            actas = actas_de_incidencia(r["incidencia_id"])
            if actas.empty:
                st.warning("Esta incidencia requiere acta pero aun no esta firmada.")
                inc = _obtener_incidencia(r["incidencia_id"])
                al = _obtener_alumno(inc["alumno_id"])
                nombre_al_default = (f"{al['apellido_paterno']} "
                                     f"{al['apellido_materno'] or ''}, "
                                     f"{al['nombres']}")
                st.write(f"**Alumno:** {nombre_al_default}")
                st.write(f"**Apoderado:** {al.get('nombre_apoderado') or '-'}")
                st.markdown("---")

                nombre_alumno = st.text_input(
                    "Nombre del alumno firmante",
                    value=nombre_al_default,
                    key=f"nom_al_{r['incidencia_id']}")
                st.caption("Firma del alumno")
                firma_alumno = firma_widget(key=f"firma_al_{r['incidencia_id']}")
                st.markdown("---")

                nombre_apoderado = st.text_input(
                    "Nombre del apoderado firmante",
                    value=al.get("nombre_apoderado") or "",
                    key=f"nom_apo_{r['incidencia_id']}")
                st.caption("Firma del apoderado")
                firma_apoderado = firma_widget(key=f"firma_apo_{r['incidencia_id']}")
                st.markdown("---")

                obs = st.text_area(
                    "Observaciones / Acuerdos (esto va dentro del PDF)",
                    key=f"obs_{r['incidencia_id']}")

                if st.button("Guardar acta y generar PDF", type="primary",
                             key=f"guardar_acta_{r['incidencia_id']}"):
                    firma_al_b64 = None
                    if firma_alumno is not None and getattr(firma_alumno, "firma_data", None):
                        firma_al_b64 = firma_alumno.firma_data
                    else:
                        firma_al_b64 = firma_guardada(f"firma_al_{r['incidencia_id']}")
                    firma_apo_b64 = None
                    if firma_apoderado is not None and getattr(firma_apoderado, "firma_data", None):
                        firma_apo_b64 = firma_apoderado.firma_data
                    else:
                        firma_apo_b64 = firma_guardada(f"firma_apo_{r['incidencia_id']}")
                    if not nombre_alumno.strip() or not nombre_apoderado.strip():
                        st.error("Nombres de alumno y apoderado obligatorios.")
                    elif not firma_al_b64 or not firma_apo_b64:
                        st.error("Faltan firmas. Firma ambos recuadros.")
                    else:
                        ok, msg = crear_acta_doble(
                            r["incidencia_id"], f"{nombre_alumno} / {nombre_apoderado}",
                            firma_al_b64, firma_apo_b64, obs,
                            nombre_alumno.strip(), nombre_apoderado.strip(),
                            st.session_state["user"])
                        if ok:
                            st.session_state.pop(f"_firma_actual_firma_al_{r['incidencia_id']}", None)
                            st.session_state.pop(f"_firma_actual_firma_apo_{r['incidencia_id']}", None)
                            st.toast(msg); st.rerun()
                        else:
                            st.error(msg)
            else:
                for _, act in actas.iterrows():
                    st.markdown(f"**Acta #{act['id']}** — "
                                f"Firmante: {act['firmante_nombre']} — "
                                f"Fecha: {act['firmado_en']}")
                    if act['observaciones']:
                        st.caption(f"Obs: {act['observaciones']}")
                    if act.get("nombre_alumno"):
                        st.caption(f"Alumno: {act['nombre_alumno']}")
                    if act.get("nombre_apoderado"):
                        st.caption(f"Apoderado: {act['nombre_apoderado']}")
                    pdf_b64 = act.get("pdf_base64")
                    if pdf_b64:
                        try:
                            pdf_bytes = base64.b64decode(pdf_b64)
                            st.download_button(
                                "Descargar PDF del acta",
                                pdf_bytes,
                                file_name=f"acta_{act['id']}.pdf",
                                mime="application/pdf",
                                key=f"pdf_acta_{act['id']}")
                        except Exception as e:
                            st.warning(f"No se pudo cargar el PDF: {e}")
                    st.markdown("---")

def _obtener_incidencia(inc_id):
    con = conn()
    cur = con.execute("SELECT * FROM incidencias WHERE id=?", (inc_id,))
    f = cur.fetchone()
    return dict(f) if f else None

def _obtener_alumno(al_id):
    con = conn()
    cur = con.execute("SELECT * FROM alumnos WHERE id=?", (al_id,))
    f = cur.fetchone()
    return dict(f) if f else None

# ── INCIDENCIAS ───────────────────────────────────────────────────────
def crear_incidencia(alumno_id, fecha, tipo, categoria, descripcion,
                     reportado_por, requiere_acta, tipo_acta, usuario):
    escribir("""INSERT INTO incidencias(alumno_id,fecha,hora,tipo,categoria,
                descripcion,reportado_por,estado,requiere_acta,tipo_acta,created_at)
                VALUES(?,?,?,?,?,?,?,'Abierta',?,?,?)""",
             (alumno_id, fecha, hora_corta(), tipo, categoria, descripcion,
              reportado_por, 1 if requiere_acta else 0,
              tipo_acta if requiere_acta else None, timestamp_str()))
    auditar(usuario["usuario"], f"Creo incidencia para alumno_id={alumno_id}",
            "incidencias")
    return True, "Incidencia registrada."

def cambiar_estado_incidencia(inc_id, nuevo_estado, usuario):
    escribir("UPDATE incidencias SET estado=? WHERE id=?",
             (nuevo_estado, inc_id))
    auditar(usuario["usuario"],
            f"Cambio estado incidencia id={inc_id} a {nuevo_estado}",
            "incidencias", inc_id)
    return True, "Estado actualizado."

def eliminar_incidencia(inc_id, usuario):
    con = conn()
    con.execute("DELETE FROM actas WHERE incidencia_id=?", (inc_id,))
    con.execute("DELETE FROM incidencias WHERE id=?", (inc_id,))
    con.commit()
    auditar(usuario["usuario"], f"Elimino incidencia id={inc_id}",
            "incidencias", inc_id)
    return True, "Incidencia eliminada."

def buscar_alumno_widget(clave):
    st.write("**Buscar alumno**")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        texto = st.text_input("Nombre", key=clave + "_buscar")
    with c2:
        dni = st.text_input("DNI", key=clave + "_dni")
    with c3:
        grados = obtener_grados()
        grado = st.selectbox("Grado", grados, key=clave + "_grado")
    with c4:
        secciones = obtener_secciones(grado)
        seccion = st.selectbox("Seccion", secciones, key=clave + "_sec")
    df = buscar_alumnos(texto, grado, seccion, dni, limite=50)
    if df.empty:
        st.warning("Sin coincidencias."); return None
    ops = {}
    for _, r in df.iterrows():
        nombre = (r['apellido_paterno'] + " " + (r['apellido_materno'] or "") +
                  ", " + r['nombres'])
        et = f"{nombre} - {r['grado'] or ''} {r['seccion'] or ''} - DNI {mask_dni(r['dni'])}"
        ops[et] = r["id"]
    sel = st.selectbox("Alumno", list(ops.keys()), key=clave + "_sel")
    idal = ops[sel]
    return _obtener_alumno(idal)

def vista_incidencias():
    st.title("Incidencias")
    pid = st.session_state.get("incidencia_ver_id")
    if pid:
        vista_detalle_incidencia(pid); return
    tabs = st.tabs(["Listar", "Crear"])

    with tabs[0]:
        c1, c2, c3 = st.columns([2, 2, 3])
        with c1:
            filtro_estado = st.selectbox("Estado", ["Todos"] + ESTADOS,
                                          key="inc_f_estado")
        with c2:
            filtro_tipo = st.selectbox("Tipo", ["Todos"] + TIPOS_INCIDENCIA,
                                        key="inc_f_tipo")
        with c3:
            filtro_texto = st.text_input("Buscar alumno",
                                          key="inc_f_texto",
                                          placeholder="Nombre o DNI")
        q = """SELECT i.id, i.fecha, i.hora, i.tipo, i.categoria, i.estado,
               i.requiere_acta, i.tipo_acta, i.descripcion,
               al.id AS alumno_id,
               al.apellido_paterno||' '||COALESCE(al.apellido_materno,'')||', '||al.nombres AS alumno,
               al.grado, al.seccion
               FROM incidencias i JOIN alumnos al ON i.alumno_id=al.id WHERE 1=1"""
        p = []
        if filtro_estado != "Todos":
            q += " AND i.estado=?"; p.append(filtro_estado)
        if filtro_tipo != "Todos":
            q += " AND i.tipo=?"; p.append(filtro_tipo)
        if filtro_texto.strip():
            pat = f"%{filtro_texto.strip()}%"
            q += " AND (al.nombres LIKE ? OR al.apellido_paterno LIKE ? OR al.dni LIKE ?)"
            p += [pat, pat, pat]
        q += " ORDER BY i.fecha DESC, i.hora DESC LIMIT 500"
        df = leer_df(q, p)
        st.write(f"{len(df)} incidencias")
        if df.empty:
            st.info("Sin incidencias.")
        else:
            for _, r in df.iterrows():
                c1, c2, c3, c4 = st.columns([2, 3, 2, 1])
                c1.write(f"**{r['fecha']}** {r['hora']}")
                c2.write(r["alumno"])
                c3.write(f"{r['tipo']} - {r['estado']}")
                if c4.button("Ver", key="ver_inc_" + str(r['id'])):
                    st.session_state["incidencia_ver_id"] = r["id"]; st.rerun()

    with tabs[1]:
        st.subheader("Nueva incidencia")
        st.caption("Para escanear QR, ve a 'Escaner QR' en el menu lateral.")
        al = buscar_alumno_widget("inc_nueva")
        if not al:
            return
        st.markdown("---")
        st.write(f"**{al['nombres']} {al['apellido_paterno']}** — "
                 f"{al['grado'] or ''} {al['seccion'] or ''} — "
                 f"DNI {mask_dni(al['dni'])}")
        with st.form("form_inc"):
            c1, c2 = st.columns(2)
            with c1:
                fecha = st.date_input("Fecha", value=ahora().date(), key="inc_fecha")
                tipo = st.selectbox("Tipo", TIPOS_INCIDENCIA, key="inc_tipo")
            with c2:
                categoria = st.selectbox("Categoria", CATEGORIAS, key="inc_cat")
                reportado = st.text_input(
                    "Reportado por",
                    value=st.session_state["user"]["nombres"],
                    key="inc_rep")
            descripcion = st.text_area("Descripcion *", key="inc_desc",
                                        placeholder="Describe lo ocurrido")
            st.markdown("---")
            requiere_acta = st.checkbox("¿Requiere acta?", key="inc_req_acta")
            tipo_acta = None
            if requiere_acta:
                tipo_acta = st.radio(
                    "Tipo de acta",
                    ["alumno", "apoderado", "alumno_apoderado"],
                    key="inc_tipo_acta", horizontal=True)
            sub = st.form_submit_button("Registrar incidencia", type="primary")
        if sub:
            if not descripcion.strip():
                st.error("La descripcion es obligatoria.")
            else:
                ok, msg = crear_incidencia(
                    al["id"], fecha.strftime("%Y-%m-%d"), tipo, categoria,
                    descripcion.strip(), reportado.strip(),
                    requiere_acta, tipo_acta, st.session_state["user"])
                if ok:
                    st.toast(msg); st.rerun()
                else:
                    st.error(msg)

def vista_detalle_incidencia(inc_id):
    if st.button("← Volver a incidencias", key="volver_inc"):
        st.session_state.pop("incidencia_ver_id", None); st.rerun()
    r = _obtener_incidencia(inc_id)
    if not r:
        st.warning("Incidencia no encontrada."); return
    al = _obtener_alumno(r["alumno_id"])
    nombre = (al['apellido_paterno'] + " " + (al['apellido_materno'] or "") +
              ", " + al['nombres'])
    st.subheader(nombre)
    st.write(f"**Grado y seccion:** {al['grado'] or ''} {al['seccion'] or ''}")
    st.write(f"**DNI:** {mask_dni(al['dni'])}")
    st.write(f"**Tipo:** {r['tipo']} — **Estado:** {r['estado']}")
    st.markdown("---")
    st.subheader("Detalle de la incidencia")
    st.write(f"**Fecha:** {r['fecha']} {r['hora']}")
    st.write(f"**Categoria:** {r['categoria'] or '-'}")
    st.write(f"**Reportado por:** {r['reportado_por']}")
    st.write(f"**Descripcion:** {r['descripcion']}")
    st.write(f"**Requiere acta:** "
             f"{'Si (' + (r['tipo_acta'] or '') + ')' if r['requiere_acta'] else 'No'}")
    st.markdown("---")
    st.subheader("Cambiar estado")
    nuevo = st.selectbox("Estado", ESTADOS,
                          index=ESTADOS.index(r["estado"]) if r["estado"] in ESTADOS else 0,
                          key="inc_nuevo_estado")
    if st.button("Actualizar estado", type="primary"):
        ok, msg = cambiar_estado_incidencia(inc_id, nuevo, st.session_state["user"])
        if ok:
            st.toast(msg); st.rerun()
    st.markdown("---")
    actas = actas_de_incidencia(inc_id)
    if r["requiere_acta"]:
        st.subheader("Actas firmadas")
        if actas.empty:
            st.warning("Falta firmar acta.")
        else:
            for _, act in actas.iterrows():
                st.write(f"**Acta #{act['id']}** — {act['tipo']} — "
                         f"Firmante: {act['firmante_nombre']} — "
                         f"{act['firmado_en']}")
                if act.get("nombre_alumno"):
                    st.caption(f"Alumno: {act['nombre_alumno']}")
                if act.get("nombre_apoderado"):
                    st.caption(f"Apoderado: {act['nombre_apoderado']}")
                pdf_b64 = act.get("pdf_base64")
                if pdf_b64:
                    try:
                        pdf_bytes = base64.b64decode(pdf_b64)
                        st.download_button(
                            "Descargar PDF del acta",
                            pdf_bytes,
                            file_name=f"acta_{act['id']}.pdf",
                            mime="application/pdf",
                            key=f"pdf_det_{act['id']}")
                    except Exception:
                        pass
                st.markdown("---")
        st.subheader("Firmar nueva acta (alumno y apoderado)")
        st.caption("El acta se genera en PDF con las observaciones como contenido.")
        nombre_al_default = nombre
        nombre_alumno = st.text_input("Nombre del alumno firmante",
                                       value=nombre_al_default,
                                       key="det_nom_al")
        st.caption("Firma del alumno")
        firma_alumno = firma_widget(key=f"firma_det_al_{inc_id}")
        st.markdown("---")
        nombre_apoderado = st.text_input(
            "Nombre del apoderado firmante",
            value=al.get("nombre_apoderado") or "",
            key="det_nom_apo")
        st.caption("Firma del apoderado")
        firma_apoderado = firma_widget(key=f"firma_det_apo_{inc_id}")
        st.markdown("---")
        obs = st.text_area("Observaciones / Acuerdos", key="det_obs")
        if st.button("Guardar acta y generar PDF", type="primary",
                     key="det_guardar_acta"):
            firma_al_b64 = None
            if firma_alumno is not None and getattr(firma_alumno, "firma_data", None):
                firma_al_b64 = firma_alumno.firma_data
            else:
                firma_al_b64 = firma_guardada(f"firma_det_al_{inc_id}")
            firma_apo_b64 = None
            if firma_apoderado is not None and getattr(firma_apoderado, "firma_data", None):
                firma_apo_b64 = firma_apoderado.firma_data
            else:
                firma_apo_b64 = firma_guardada(f"firma_det_apo_{inc_id}")
            if not nombre_alumno.strip() or not nombre_apoderado.strip():
                st.error("Nombres de alumno y apoderado obligatorios.")
            elif not firma_al_b64 or not firma_apo_b64:
                st.error("Faltan firmas.")
            else:
                ok, msg = crear_acta_doble(
                    inc_id, f"{nombre_alumno} / {nombre_apoderado}",
                    firma_al_b64, firma_apo_b64, obs,
                    nombre_alumno.strip(), nombre_apoderado.strip(),
                    st.session_state["user"])
                if ok:
                    st.session_state.pop(f"_firma_actual_firma_det_al_{inc_id}", None)
                    st.session_state.pop(f"_firma_actual_firma_det_apo_{inc_id}", None)
                    st.toast(msg); st.rerun()
                else:
                    st.error(msg)

# ── PERFIL ALUMNO ─────────────────────────────────────────────────────
def vista_perfil_alumno(idal):
    if st.button("← Volver a alumnos", key="volver_perfil_al"):
        st.session_state.pop("alumno_perfil_id", None); st.rerun()
    al = _obtener_alumno(idal)
    if not al:
        st.warning("Alumno no encontrado."); return
    nombre = (al['apellido_paterno'] + " " + (al['apellido_materno'] or "") +
              ", " + al['nombres'])
    st.title(nombre)
    st.write(f"**Grado y seccion:** {al['grado'] or ''} {al['seccion'] or ''}")
    st.write(f"**Turno:** {al['turno'] or '-'}")
    st.write(f"**DNI:** {mask_dni(al['dni'])}")
    st.write(f"**Estado:** {'ACTIVO' if al['activo'] else 'INACTIVO'}")
    st.markdown("---")
    st.subheader("Datos del apoderado")
    st.write(f"**Nombre:** {al.get('nombre_apoderado') or '-'}")
    st.write(f"**Telefono:** {al.get('telefono_apoderado') or '-'}")
    st.write(f"**Email:** {al.get('email_apoderado') or '-'}")
    st.write(f"**Direccion:** {al.get('direccion') or '-'}")
    st.write(f"**Fecha de nacimiento:** {al.get('fecha_nacimiento') or '-'}")
    st.markdown("---")
    incs = leer_df("""SELECT id,fecha,hora,tipo,categoria,estado,requiere_acta,
                      tipo_acta,descripcion,reportado_por
                      FROM incidencias WHERE alumno_id=?
                      ORDER BY fecha DESC, hora DESC""", (idal,))
    n_total = len(incs)
    n_abiertas = int((incs["estado"] == "Abierta").sum()) if not incs.empty else 0
    n_proceso = int((incs["estado"] == "En proceso").sum()) if not incs.empty else 0
    n_resueltas = int((incs["estado"] == "Resuelta").sum()) if not incs.empty else 0
    n_archivadas = int((incs["estado"] == "Archivada").sum()) if not incs.empty else 0
    n_leves = int((incs["tipo"] == "Leve").sum()) if not incs.empty else 0
    n_graves = int((incs["tipo"] == "Grave").sum()) if not incs.empty else 0
    n_muy = int((incs["tipo"] == "Muy grave").sum()) if not incs.empty else 0
    st.subheader("Estadisticas de incidencias")
    c1, c2, c3, c4, c5, c6, c7, c8 = st.columns(8)
    c1.metric("Total", n_total)
    c2.metric("Abiertas", n_abiertas)
    c3.metric("En proceso", n_proceso)
    c4.metric("Resueltas", n_resueltas)
    c5.metric("Archivadas", n_archivadas)
    c6.metric("Leves", n_leves)
    c7.metric("Graves", n_graves)
    c8.metric("Muy graves", n_muy)
    st.markdown("---")
    st.subheader("Historial de incidencias")
    if incs.empty:
        st.info("Sin incidencias registradas.")
    else:
        for _, r in incs.iterrows():
            with st.expander(f"{r['fecha']} {r['hora']} - {r['tipo']} ({r['estado']})"):
                st.write(f"**Categoria:** {r['categoria'] or '-'}")
                st.write(f"**Reportado por:** {r['reportado_por']}")
                st.write(f"**Descripcion:** {r['descripcion']}")
                if r["requiere_acta"]:
                    st.caption(f"Requiere acta ({r['tipo_acta'] or '-'})")
                if st.button("Ver detalle", key=f"ver_inc_perf_{r['id']}"):
                    st.session_state["incidencia_ver_id"] = r["id"]; st.rerun()
    st.markdown("---")
    st.subheader("Editar datos del alumno")
    with st.form("editar_al_perfil"):
        c1, c2 = st.columns(2)
        with c1:
            grado = st.text_input("Grado", value=al.get("grado") or "",
                                   key="ed_grado")
            seccion = st.text_input("Seccion", value=al.get("seccion") or "",
                                     key="ed_sec")
            turno = st.selectbox("Turno", ["", "Mañana", "Tarde"],
                                  index=(["", "Mañana", "Tarde"].index(al["turno"])
                                         if al.get("turno") in ["", "Mañana", "Tarde"] else 0),
                                  key="ed_tur")
        with c2:
            apo_n = st.text_input("Apoderado",
                                   value=al.get("nombre_apoderado") or "",
                                   key="ed_apo")
            apo_t = st.text_input("Telefono apoderado",
                                   value=al.get("telefono_apoderado") or "",
                                   key="ed_tel")
            email_apo = st.text_input("Email apoderado",
                                       value=al.get("email_apoderado") or "",
                                       key="ed_email")
        direccion = st.text_input("Direccion",
                                   value=al.get("direccion") or "",
                                   key="ed_dir")
        fn = None
        if al.get("fecha_nacimiento"):
            try:
                fn = datetime.strptime(al["fecha_nacimiento"], "%Y-%m-%d").date()
            except Exception:
                fn = None
        fecha_nac = st.date_input("Fecha de nacimiento", value=fn, key="ed_fnac")
        if st.form_submit_button("Guardar cambios", type="primary"):
            fn_s = fecha_nac.strftime("%Y-%m-%d") if fecha_nac else None
            editar_alumno(idal, grado, seccion, turno, apo_n, apo_t,
                          direccion, fn_s, email_apo, st.session_state["user"])
            st.toast("Datos actualizados."); st.rerun()
    if st.session_state["user"]["rol"] in ("Admin", "Direccion"):
        st.markdown("---")
        st.subheader("Zona critica")
        if al["activo"]:
            if st.button("Desactivar alumno", key="desact_al"):
                retirar_alumno(idal, st.session_state["user"])
                st.toast("Alumno desactivado."); st.rerun()
        else:
            if st.button("Reactivar alumno", key="react_al"):
                reactivar_alumno(idal, st.session_state["user"])
                st.toast("Alumno reactivado."); st.rerun()

# ── REPORTES ──────────────────────────────────────────────────────────
def reporte_diario_incidencias(fecha):
    return leer_df("""
        SELECT i.id, i.fecha, i.hora, i.tipo, i.categoria, i.estado,
        al.apellido_paterno||' '||COALESCE(al.apellido_materno,'')||', '||al.nombres AS Alumno,
        al.grado AS Grado, al.seccion AS Seccion,
        al.dni AS DNI, i.descripcion AS Descripcion,
        i.reportado_por AS "Reportado por",
        CASE WHEN i.requiere_acta=1 THEN 'Si ('||COALESCE(i.tipo_acta,'')||')' ELSE 'No' END AS "Requiere acta"
        FROM incidencias i JOIN alumnos al ON i.alumno_id=al.id
        WHERE i.fecha=?
        ORDER BY i.hora DESC
    """, (fecha,))

def reporte_mensual_incidencias(anio, mes):
    ini = f"{anio:04d}-{mes:02d}-01"
    if mes == 12:
        fin = f"{anio+1:04d}-01-01"
    else:
        fin = f"{anio:04d}-{mes+1:02d}-01"
    return leer_df("""
        SELECT i.id, i.fecha, i.hora, i.tipo, i.categoria, i.estado,
        al.apellido_paterno||' '||COALESCE(al.apellido_materno,'')||', '||al.nombres AS Alumno,
        al.grado AS Grado, al.seccion AS Seccion,
        al.dni AS DNI, i.descripcion AS Descripcion,
        i.reportado_por AS "Reportado por",
        CASE WHEN i.requiere_acta=1 THEN 'Si ('||COALESCE(i.tipo_acta,'')||')' ELSE 'No' END AS "Requiere acta"
        FROM incidencias i JOIN alumnos al ON i.alumno_id=al.id
        WHERE i.fecha >= ? AND i.fecha < ?
        ORDER BY i.fecha DESC, i.hora DESC
    """, (ini, fin))

def vista_reportes():
    st.title("Reportes")
    tabs = st.tabs(["Diario", "Mensual", "Por alumno", "Por tipo"])

    with tabs[0]:
        st.subheader("Reporte diario de incidencias")
        fecha = st.date_input("Fecha", value=ahora().date(), key="rep_fecha")
        df = reporte_diario_incidencias(fecha.strftime("%Y-%m-%d"))
        if df.empty:
            st.info("Sin incidencias ese dia.")
        else:
            df_show = df.copy()
            if "DNI" in df_show.columns:
                df_show["DNI"] = df_show["DNI"].apply(mask_dni)
            st.write(f"{len(df)} incidencias")
            st.dataframe(df_show, use_container_width=True)
            c1, c2 = st.columns(2)
            with c1:
                buf = BytesIO()
                with pd.ExcelWriter(buf, engine="openpyxl") as w:
                    df.to_excel(w, index=False, sheet_name="Incidencias")
                buf.seek(0)
                st.download_button("Descargar Excel", buf.getvalue(),
                                   f"incidencias_{fecha}.xlsx",
                                   "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                   use_container_width=True)
            with c2:
                csv = df.to_csv(index=False).encode("utf-8")
                st.download_button("Descargar CSV", csv,
                                   f"incidencias_{fecha}.csv", "text/csv",
                                   use_container_width=True)

    with tabs[1]:
        st.subheader("Reporte mensual de incidencias")
        c1, c2 = st.columns(2)
        with c1:
            anio = st.number_input("Año", min_value=2020, max_value=2100,
                                   value=ahora().year, step=1, key="rep_anio")
        with c2:
            mes = st.selectbox("Mes", list(range(1, 13)),
                               index=ahora().month - 1, key="rep_mes")
        df = reporte_mensual_incidencias(int(anio), int(mes))
        if df.empty:
            st.info("Sin incidencias ese mes.")
        else:
            df_show = df.copy()
            if "DNI" in df_show.columns:
                df_show["DNI"] = df_show["DNI"].apply(mask_dni)
            st.write(f"{len(df)} incidencias en el mes")
            st.markdown("**Resumen por tipo**")
            resumen = df.groupby("tipo").size().reset_index(name="Total")
            st.dataframe(resumen, use_container_width=True)
            st.markdown("**Resumen por estado**")
            resumen_e = df.groupby("estado").size().reset_index(name="Total")
            st.dataframe(resumen_e, use_container_width=True)
            st.dataframe(df_show, use_container_width=True)
            buf = BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as w:
                df.to_excel(w, index=False, sheet_name="Mensual")
                resumen.to_excel(w, index=False, sheet_name="Por tipo")
                resumen_e.to_excel(w, index=False, sheet_name="Por estado")
            buf.seek(0)
            st.download_button("Descargar Excel",
                               buf.getvalue(),
                               f"incidencias_{anio}_{mes:02d}.xlsx",
                               "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    with tabs[2]:
        st.subheader("Incidencias por alumno")
        df = leer_df("""
            SELECT al.apellido_paterno||' '||COALESCE(al.apellido_materno,'')||', '||al.nombres AS Alumno,
            al.grado AS Grado, al.seccion AS Seccion,
            COUNT(*) AS Total,
            SUM(CASE WHEN i.tipo='Leve' THEN 1 ELSE 0 END) AS Leves,
            SUM(CASE WHEN i.tipo='Grave' THEN 1 ELSE 0 END) AS Graves,
            SUM(CASE WHEN i.tipo='Muy grave' THEN 1 ELSE 0 END) AS "Muy graves"
            FROM incidencias i JOIN alumnos al ON i.alumno_id=al.id
            GROUP BY al.id ORDER BY Total DESC
        """)
        if df.empty:
            st.info("Sin datos.")
        else:
            st.dataframe(df, use_container_width=True)
            buf = BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as w:
                df.to_excel(w, index=False, sheet_name="Por alumno")
            buf.seek(0)
            st.download_button("Descargar Excel", buf.getvalue(),
                               "incidencias_por_alumno.xlsx",
                               "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    with tabs[3]:
        st.subheader("Incidencias por tipo")
        df = leer_df("""
            SELECT tipo AS Tipo, categoria AS Categoria, COUNT(*) AS Total
            FROM incidencias GROUP BY tipo, categoria ORDER BY tipo, Total DESC
        """)
        if df.empty:
            st.info("Sin datos.")
        else:
            st.dataframe(df, use_container_width=True)
            buf = BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as w:
                df.to_excel(w, index=False, sheet_name="Por tipo")
            buf.seek(0)
            st.download_button("Descargar Excel", buf.getvalue(),
                               "incidencias_por_tipo.xlsx",
                               "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

# ── USUARIOS ──────────────────────────────────────────────────────────
def vista_usuarios():
    st.title("Usuarios")
    u = st.session_state["user"]
    soy_principal = (u["usuario"] == "admin")
    tabs = st.tabs(["Listar", "Crear", "Editar"])

    with tabs[0]:
        df = leer_df("SELECT id,usuario,rol,nombres,activo,ultimo_login "
                     "FROM usuarios ORDER BY usuario")
        if df.empty:
            st.info("Sin usuarios.")
        else:
            st.dataframe(df, use_container_width=True)

    with tabs[1]:
        st.subheader("Crear usuario")
        c1, c2 = st.columns(2)
        with c1:
            nu = st.text_input("Usuario", key="cr_u")
            np = st.text_input("Contraseña", type="password", key="cr_p")
        with c2:
            nn = st.text_input("Nombres", key="cr_n")
            roles = (["Admin", "Direccion", "Auxiliar"]
                     if soy_principal else ["Direccion", "Auxiliar"])
            nr = st.selectbox("Rol", roles, key="cr_r")
        if st.button("Crear", type="primary"):
            if not nu or not np or not nn:
                st.error("Completa todo.")
            elif len(np) < 6:
                st.error("Minimo 6 caracteres.")
            else:
                try:
                    escribir("INSERT INTO usuarios(usuario,password,rol,nombres) "
                             "VALUES(?,?,?,?)",
                             (nu.strip().lower(), hashear_password(np),
                              nr, nn.strip()))
                    auditar(u["usuario"], f"Creo usuario {nu}")
                    st.toast("Usuario creado."); st.rerun()
                except Exception as e:
                    st.error(f"Error: {e}")

    with tabs[2]:
        df = leer_df("SELECT id,usuario,rol,nombres,activo FROM usuarios "
                     "WHERE usuario!='admin'")
        if df.empty:
            st.info("Sin usuarios editables.")
        else:
            ops = {f"{r['usuario']} ({r['rol']})": r["id"]
                   for _, r in df.iterrows()}
            sel = st.selectbox("Usuario", list(ops.keys()), key="ed_u_sel")
            idu = ops[sel]
            d = _obtener_usuario(idu)
            with st.form("ed_u"):
                nusu = st.text_input("Usuario", value=d["usuario"])
                nnom = st.text_input("Nombres", value=d["nombres"])
                npass = st.text_input("Nueva contraseña (opcional)", type="password")
                roles = (["Admin", "Direccion", "Auxiliar"]
                         if soy_principal else ["Direccion", "Auxiliar"])
                idx_rol = roles.index(d["rol"]) if d["rol"] in roles else 0
                nrol = st.selectbox("Rol", roles, index=idx_rol)
                act = st.checkbox("Activo", value=bool(d["activo"]))
                if st.form_submit_button("Guardar", type="primary"):
                    if npass:
                        escribir("""UPDATE usuarios SET usuario=?,nombres=?,
                                    rol=?,password=?,activo=? WHERE id=?""",
                                 (nusu.strip().lower(), nnom, nrol,
                                  hashear_password(npass),
                                  1 if act else 0, idu))
                    else:
                        escribir("""UPDATE usuarios SET usuario=?,nombres=?,
                                    rol=?,activo=? WHERE id=?""",
                                 (nusu.strip().lower(), nnom, nrol,
                                  1 if act else 0, idu))
                    auditar(u["usuario"], f"Edito usuario {nusu}")
                    st.toast("Usuario editado."); st.rerun()

def _obtener_usuario(idu):
    con = conn()
    cur = con.execute("SELECT * FROM usuarios WHERE id=?", (idu,))
    f = cur.fetchone()
    return dict(f) if f else None

# ── AUDITORIA ─────────────────────────────────────────────────────────
def vista_auditoria():
    st.title("Auditoria")
    df = leer_df("SELECT id,usuario,accion,fecha,tabla_afectada,registro_id "
                 "FROM auditoria ORDER BY id DESC LIMIT 500")
    st.write(f"{len(df)} registros")
    if not df.empty:
        st.dataframe(df, use_container_width=True)

# ── Main ──────────────────────────────────────────────────────────────
def main():
    st.set_page_config(page_title="Incidencias Escolares",
                       page_icon="📋", layout="wide",
                       initial_sidebar_state="expanded")
    try:
        inicializar()
        if not st.session_state.get("user"):
            vista_login(); return
        op = menu_lateral()
        RUTAS = {
            "Escaner QR": vista_escaner,
            "Incidencias": vista_incidencias,
            "Alumnos": vista_alumnos,
            "Actas": vista_actas,
            "Reportes": vista_reportes,
            "Usuarios": vista_usuarios,
            "Auditoria": vista_auditoria,
            "Mi cuenta": vista_mi_cuenta,
        }
        v = RUTAS.get(op)
        if not v:
            st.warning("Vista no disponible."); return
        if op not in obtener_opciones_por_rol(st.session_state["user"]):
            st.error("Sin permisos."); return
        v()
    except Exception as e:
        st.error(f"Error inesperado: {e}")
        log.exception("Error en main")

if __name__ == "__main__":
    main()