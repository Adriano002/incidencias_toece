"""
firma_component.py
Componente de firma digital para Streamlit.

Uso:
    from firma_component import firma_widget, firma_guardada, limpiar_firma

    # En tu vista:
    resultado = firma_widget(key=f"firma_al_{inc_id}")
    if resultado and resultado.firma_data:
        firma_b64 = resultado.firma_data

    # O leer la última firma guardada:
    firma_b64 = firma_guardada(f"firma_al_{inc_id}")

    # Limpiar la firma cuando ya la guardaste en la BD:
    limpiar_firma(f"firma_al_{inc_id}")
"""
import re
import streamlit as st
import streamlit.components.v1 as _components

# ═══════════════════════════════════════════════════════════════════════
# HTML / CSS / JS DEL COMPONENTE
# ═══════════════════════════════════════════════════════════════════════
_HTML_TEMPLATE = """
<div class="firma-wrapper-__KEY__">
    <canvas class="firma-canvas-__KEY__" width="600" height="220"></canvas>
    <div class="firma-botones-__KEY__">
        <button class="btn-limpiar-__KEY__" type="button">Limpiar</button>
    </div>
    <div class="firma-hint-__KEY__">Firma con el mouse o con el dedo</div>
</div>
"""

_CSS_TEMPLATE = """
.firma-wrapper-__KEY__ {
    max-width: 620px;
    margin: 0 auto;
    background: #FAFAFA;
    border: 2px dashed #0A3D91;
    border-radius: 10px;
    padding: 10px;
}
.firma-canvas-__KEY__ {
    width: 100%;
    background: #FFF;
    border-radius: 6px;
    cursor: crosshair;
    touch-action: none;
    border: 1px solid #DDD;
    display: block;
}
.firma-botones-__KEY__ {
    display: flex;
    justify-content: center;
    margin-top: 8px;
}
.btn-limpiar-__KEY__ {
    background: #0A3D91;
    color: #FFF;
    border: none;
    border-radius: 6px;
    padding: 8px 20px;
    font-weight: 700;
    cursor: pointer;
    font-size: 14px;
}
.btn-limpiar-__KEY__:hover {
    background: #072A63;
}
.firma-hint-__KEY__ {
    text-align: center;
    font-size: 12px;
    color: #888;
    margin-top: 6px;
}
"""

_JS_TEMPLATE = """
export default function(component) {
    const { setTriggerValue, data } = component;
    const key = (data && data.key) ? data.key : 'default';
    const canvas = document.querySelector('.firma-canvas-' + key);
    const btnLimpiar = document.querySelector('.btn-limpiar-' + key);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let dibujando = false;
    let huboTrazo = false;
    ctx.lineWidth = 2.5;
    ctx.lineCap = 'round';
    ctx.strokeStyle = '#111';

    function pos(e) {
        const r = canvas.getBoundingClientRect();
        const cx = (e.touches ? e.touches[0].clientX : e.clientX) - r.left;
        const cy = (e.touches ? e.touches[0].clientY : e.clientY) - r.top;
        return [cx * (canvas.width / r.width), cy * (canvas.height / r.height)];
    }
    function start(e) {
        e.preventDefault();
        dibujando = true;
        const [x, y] = pos(e);
        ctx.beginPath();
        ctx.moveTo(x, y);
    }
    function move(e) {
        if (!dibujando) return;
        e.preventDefault();
        const [x, y] = pos(e);
        ctx.lineTo(x, y);
        ctx.stroke();
        huboTrazo = true;
    }
    function end(e) {
        if (!dibujando) return;
        e.preventDefault();
        dibujando = false;
        if (huboTrazo) {
            setTriggerValue("firma_data", canvas.toDataURL('image/png'));
        }
    }

    canvas.addEventListener('mousedown', start);
    canvas.addEventListener('mousemove', move);
    canvas.addEventListener('mouseup', end);
    canvas.addEventListener('mouseleave', end);
    canvas.addEventListener('touchstart', start, { passive: false });
    canvas.addEventListener('touchmove', move, { passive: false });
    canvas.addEventListener('touchend', end);

    if (btnLimpiar) {
        btnLimpiar.addEventListener('click', () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            huboTrazo = false;
            setTriggerValue("firma_data", "");
        });
    }
}
"""

# ═══════════════════════════════════════════════════════════════════════
# CACHÉ DE COMPONENTES POR KEY (evita re-registrar)
# ═══════════════════════════════════════════════════════════════════════
_COMPONENT_CACHE = {}


def _safe_key(key: str) -> str:
    """Convierte cualquier key en un identificador válido."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", str(key))


def _get_component(key: str):
    """Devuelve (y cachea) el componente único para esa key."""
    if key in _COMPONENT_CACHE:
        return _COMPONENT_CACHE[key]
    safe = _safe_key(key)
    html = _HTML_TEMPLATE.replace("__KEY__", safe)
    css = _CSS_TEMPLATE.replace("__KEY__", safe)
    comp = st.components.v2.component(
        name=f"firma_canvas_{safe}",
        isolate_styles=False,
        html=html,
        css=css,
        js=_JS_TEMPLATE,
    )
    _COMPONENT_CACHE[key] = comp
    return comp


# ═══════════════════════════════════════════════════════════════════════
# API PÚBLICA
# ═══════════════════════════════════════════════════════════════════════
def firma_widget(key: str = "firma"):
    """
    Renderiza un canvas de firma.

    Devuelve el objeto result del componente si tiene firma_data,
    o None si aún no se ha dibujado.
    """
    comp = _get_component(key)
    safe = _safe_key(key)
    result = comp(key=key, data={"key": safe})
    if result is not None and getattr(result, "firma_data", None):
        st.session_state[f"_firma_actual_{key}"] = result.firma_data
    return result


def firma_guardada(key: str):
    """Devuelve la última firma guardada en session_state o None."""
    return st.session_state.get(f"_firma_actual_{key}")


def limpiar_firma(key: str):
    """Borra la firma guardada del session_state."""
    st.session_state.pop(f"_firma_actual_{key}", None)


def tiene_firma(key: str) -> bool:
    """True si hay una firma guardada para esa key."""
    return bool(st.session_state.get(f"_firma_actual_{key}"))
