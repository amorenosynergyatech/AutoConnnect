import { useEffect, useState } from "react";
import "./App.css";
import appIcon from "./assets/app-icon.png";
import { invoke } from "@tauri-apps/api/tauri";

export default function App() {
  // Colores más vivos
  const colores = {
    rojo: "#ff3b30",   // rojo vivo
    verde: "#34c759",  // verde brillante
    naranja: "#ff9f0a" // naranja intenso
  };

  const [estado, setEstado] = useState("rojo");
  const [showConfig, setShowConfig] = useState(false);

  // Estado del formulario de configuración
  const [urlapp, setUrlapp] = useState("");
  const [websocketip, setWebsocketip] = useState("");
  const [websocketpuerto, setWebsocketpuerto] = useState("");

  const RUST_STATUS_URL = "http://127.0.0.1:5201/status";

  useEffect(() => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
    }, 3000);

    fetch(RUST_STATUS_URL, { signal: controller.signal })
      .then((res) => {
        clearTimeout(timeoutId);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(() => invoke("call_api_cargar_doc_ordenes_backend"))
      .then(() => setEstado("verde"))
      .catch((err) => {
        clearTimeout(timeoutId);
        console.error("[Estado Rust]", err.name, err.message);
        if (err.name === "TypeError" || err.name === "AbortError") {
          setEstado("naranja");
        } else {
          setEstado("rojo");
        }
      });
  }, []);

  const toggleConfig = () => setShowConfig((v) => !v);

  const handleGuardar = (e) => {
    e.preventDefault();
    // Aquí podrías persistir en backend/tauri si lo deseas.
    // Ejemplo (opcional): invoke("guardar_config", { urlapp, websocketip, websocketpuerto })
    console.log("Configuración guardada:", { urlapp, websocketip, websocketpuerto });
    setShowConfig(false);
  };

  return (
    <main className="menu">
      <header className="cabecera">
        <div className="logo">
          <img src={appIcon} alt="businessconnect icon" className="logo__img" />
        </div>

        <h1 className="titulo">Autocontact IA Connector</h1>

        {/* Botón arriba a la derecha */}
        <button
          type="button"
          className="config-btn"
          aria-label={showConfig ? "Volver" : "Abrir configuración"}
          title={showConfig ? "Volver" : "Configuración"}
          onClick={toggleConfig}
        >
          {/* Icono: engranaje / flecha según vista */}
          {showConfig ? (
            // Flecha volver
            <svg viewBox="0 0 24 24" className="icon">
              <path d="M20 11H7.83l4.58-4.59L11 5l-7 7 7 7 1.41-1.41L7.83 13H20v-2z"/>
            </svg>
          ) : (
            // Engranaje
            <svg viewBox="0 0 24 24" className="icon">
              <path d="M19.14,12.94a7.14,7.14,0,0,0,.05-.94,7.14,7.14,0,0,0-.05-.94l2.11-1.65a.48.48,0,0,0,.11-.62l-2-3.46a.5.5,0,0,0-.6-.22l-2.49,1a7.34,7.34,0,0,0-1.63-.94l-.38-2.65A.49.49,0,0,0,13.77,2H10.23a.49.49,0,0,0-.49.41L9.36,5.06a7.34,7.34,0,0,0-1.63.94l-2.49-1a.5.5,0,0,0-.6.22l-2,3.46a.48.48,0,0,0,.11.62L4.86,11.06a7.14,7.14,0,0,0-.05.94,7.14,7.14,0,0,0,.05.94L2.75,14.59a.48.48,0,0,0-.11.62l2,3.46a.5.5,0,0,0,.6.22l2.49-1a7.34,7.34,0,0,0,1.63.94l.38,2.65a.49.49,0,0,0,.49.41h3.54a.49.49,0,0,0,.49-.41l.38-2.65a7.34,7.34,0,0,0,1.63-.94l2.49,1a.5.5,0,0,0,.6-.22l2-3.46a.48.48,0,0,0-.11-.62ZM12,15.5A3.5,3.5,0,1,1,15.5,12,3.5,3.5,0,0,1,12,15.5Z"/>
            </svg>
          )}
        </button>
      </header>

      <hr className="divider" />

      {showConfig ? (
        /* PANTALLA DE CONFIGURACIÓN */
        <section className="config">
          <h2 className="subtitulo">Configuración</h2>
          <form className="form" onSubmit={handleGuardar}>
            <div className="form-group">
              <label htmlFor="urlapp">URL App</label>
              <input
                id="urlapp"
                type="text"
                value={urlapp}
                onChange={(e) => setUrlapp(e.target.value)}
                placeholder="https://mi-app.com"
                className="input"
              />
            </div>

            <div className="form-group">
              <label htmlFor="websocketip">IP</label>
              <input
                id="websocketip"
                type="text"
                value={websocketip}
                onChange={(e) => setWebsocketip(e.target.value)}
                placeholder="127.0.0.1"
                className="input"
              />
            </div>

            <div className="form-group">
              <label htmlFor="websocketpuerto">Puerto</label>
              <input
                id="websocketpuerto"
                type="number"
                value={websocketpuerto}
                onChange={(e) => setWebsocketpuerto(e.target.value)}
                placeholder="8080"
                className="input"
                min="0"
              />
            </div>

            <div className="acciones-form">
              <button type="submit" className="btn btn-primary">Guardar</button>
              <button type="button" className="btn" onClick={() => setShowConfig(false)}>
                Cancelar
              </button>
            </div>
          </form>
        </section>
      ) : (
        /* PANTALLA DE ESTADO */
        <section className="estado">
          <span className="estado__label">Estado</span>
          <span
            className="estado__indicador"
            style={{ backgroundColor: colores[estado] }}
          />
        </section>
      )}
    </main>
  );
}
