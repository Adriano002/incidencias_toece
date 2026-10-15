# qr_scanner_component.py
import streamlit as st

QR_SCANNER = st.components.v2.component(
    name="qr_scanner_v5",
    isolate_styles=False,
    html="""
    <div id="qr-reader"></div>
    """,
    css="""
    #qr-reader{width:100%;max-width:520px;margin:0 auto;
        border:1px solid #CCC;border-radius:8px;overflow:hidden;background:#000;}
    #qr-reader__dashboard{display:none;}
    """,
    js="""
    export default function(component){
        const { setTriggerValue } = component;
        let scanner = null;
        let ultimo = "";
        let ultimoTs = 0;

        function cargarLibreria(cb){
            if (window.Html5Qrcode) { cb(); return; }
            const s = document.createElement('script');
            s.src = "https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js";
            s.onload = cb;
            document.head.appendChild(s);
        }

        cargarLibreria(() => {
            scanner = new Html5Qrcode("qr-reader", { verbose: false });
            scanner.start(
                { facingMode: "environment" },
                { fps: 10, qrbox: { width: 250, height: 250 } },
                (texto) => {
                    const ahora = Date.now();
                    if (texto === ultimo && (ahora - ultimoTs) < 3000) return;
                    ultimo = texto;
                    ultimoTs = ahora;
                    setTriggerValue("qr_dni", texto);
                },
                () => {}
            ).catch((e) => { console.error("Error camara:", e); });
        });

        return () => {
            if (scanner) {
                try { scanner.stop().then(() => scanner.clear()).catch(()=>{}); }
                catch(e){}
            }
        };
    }
    """,
)

def qr_scanner(key="qr", on_scan=None):
    return QR_SCANNER(key=key)