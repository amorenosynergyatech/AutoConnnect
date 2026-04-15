import { useEffect, useState } from "react";
import "./App.css";
import appIcon from "./assets/app-icon.png";
import { invoke } from "@tauri-apps/api/tauri";

export default function App() {
  const colores = {
    rojo: "#ff3b30",
    verde: "#34c759",
    naranja: "#ff9f0a",
  };

  const [estado, setEstado] = useState("rojo");
  const [showConfig, setShowConfig] = useState(false);

  // Estado del formulario de configuración
  const [urlapp, setUrlapp] = useState("");
  const [websocketip, setWebsocketip] = useState("");
  const [websocketpuerto, setWebsocketpuerto] = useState("");
  const [usuario, setUsuario] = useState("");
  const [contrasena, setContrasena] = useState("");

  // 🔥 Nuevo: reemplaza ipservidor → server
  const [server, setServer] = useState("");

  const [qaeServer, setQaeServer] = useState("");
  const [qaePort, setQaePort] = useState("");

  // Tabs
  const [activeTab, setActiveTab] = useState("dms");

  // QAE
  const [useQae, setUseQae] = useState(false);
  const [usuarioQae, setUsuarioQae] = useState("");
  const [contrasenaQae, setContrasenaQae] = useState("");

  // QAC
  const [useQac, setUseQac] = useState(false);
  const [usuarioQac, setUsuarioQac] = useState("");
  const [contrasenaQac, setContrasenaQac] = useState("");

  // API URL
  const [apiUrl, setApiUrl] = useState("");

  const [SECRET_KEY, setKey] = useState("");
  useEffect(() => {
    invoke("obtener_contrasena_encrypt").then(setKey).catch(console.error);
  }, []);

  const etiquetas = {
    rojo: "Desconectado",
    naranja: "Intentando",
    verde: "Conectado",
  };

  const [dms, setDms] = useState({
    quiter: false,
    star: false,
  });

  const handleDmsChange = (name) => {
    setDms({
      quiter: name === "quiter",
      star: name === "star",
    });
  };

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

  useEffect(() => {
    if (showConfig && SECRET_KEY) {
      invoke("obtener_config_sqlite", { key: SECRET_KEY })
        .then((cfg) => {
          console.log("CONFIG RECIBIDA:", cfg);
          if (!cfg) return;

          setServer(cfg.server || "");
          setUsuario(cfg.username || "");
          setContrasena(cfg.password || "");
          setWebsocketpuerto(cfg.puertoagente || "");
          setDms({ quiter: !!cfg.usequiter, star: !!cfg.usestar });

          // 🔥 QAE
          setUseQae(!!cfg.useqae);
          setUsuarioQae(cfg.usuarioqae || "");
          setContrasenaQae(cfg.contrasenaqae || "");

          // 👇 AÑADE ESTO
          setQaeServer(cfg.qaeserver || "");
          setQaePort(cfg.qaeport || "");

          setUseQac(!!cfg.useqac);
          setUsuarioQac(cfg.usuarioqac || "");
          setContrasenaQac(cfg.contrasenaqac || "");

          setApiUrl(cfg.apiurl || "");
        })
        .catch((e) => console.error("Leer config:", e));
    }
  }, [showConfig, SECRET_KEY]);

  const handleGuardar = async (e) => {
    e.preventDefault();
    try {
      await invoke("guardar_config_sqlite", {
        server,
        username: usuario,
        password: contrasena,
        puertoagente: websocketpuerto,
        usequiter: dms.quiter ? 1 : 0,
        usestar: dms.star ? 1 : 0,

        // 🔥 QAE
        useqae: useQae ? 1 : 0,
        usuarioqae: usuarioQae,
        contrasenaqae: contrasenaQae,
        qaeserver: qaeServer,
        qaeport: qaePort,

        // QAC
        useqac: useQac ? 1 : 0,
        usuarioqac: usuarioQac,
        contrasenaqac: contrasenaQac,

        apiurl: apiUrl,

        key: SECRET_KEY,
      });
      setShowConfig(false);
    } catch (err) {
      console.error("Guardar config:", err);
    }
  };

  const handleObtenerCredencialesQAC = async () => {
    try {
      const input_json = {
        comando: "credencialesQAC"
      };

      console.log("📤 Enviando:", input_json);

      const result = await invoke("api_command_py", {
        inputJson: JSON.stringify(input_json)
      });

      console.log("📥 Respuesta RAW:", result);

      try {
        const parsed = JSON.parse(result);
        console.log("📦 Respuesta PARSEADA:", parsed);
      } catch (e) {
        console.warn("⚠️ No se pudo parsear JSON");
      }

      console.log("✅ Credenciales QAC obtenidas:", result);
    } catch (error) {
      console.error("❌ Error ejecutando credencialesQAC:", error);
    }
  };

  const toggleConfig = () => setShowConfig((v) => !v);

  return (
    <main className="menu">
      <header className="cabecera">
        <div className="logo">
          <img src={appIcon} alt="businessconnect icon" className="logo__img" />
        </div>

        <h1 className="titulo">Autocontact IA Connector</h1>

        <button
          type="button"
          className="config-btn"
          aria-label={showConfig ? "Volver" : "Abrir configuración"}
          title={showConfig ? "Volver" : "Configuración"}
          onClick={toggleConfig}
        >
          {showConfig ? (
            <svg viewBox="0 0 24 24" className="icon">
              <path d="M20 11H7.83l4.58-4.59L11 5l-7 7 7 7 1.41-1.41L7.83 13H20v-2z" />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" className="icon">
              <path d="M19.14,12.94a7.14,7.14,0,0,0,.05-.94,7.14,7.14,0,0,0-.05-.94l2.11-1.65a.48.48,0,0,0,.11-.62l-2-3.46a.5.5,0,0,0-.6-.22l-2.49,1a7.34,7.34,0,0,0-1.63-.94l-.38-2.65A.49.49,0,0,0,13.77,2H10.23a.49.49,0,0,0-.49.41L9.36,5.06a7.34,7.34,0,0,0-1.63.94l-2.49-1a.5.5,0,0,0-.6.22l-2,3.46a.48.48,0,0,0,.11.62L4.86,11.06a7.14,7.14,0,0,0-.05.94,7.14,7.14,0,0,0,.05.94L2.75,14.59a.48.48,0,0,0-.11.62l2,3.46a.5.5,0,0,0,.6.22l2.49-1a7.34,7.34,0,0,0,1.63.94l.38,2.65a.49.49,0,0,0,.49.41h3.54a.49.49,0,0,0,.49-.41l.38-2.65a7.34,7.34,0,0,0,1.63-.94l2.49,1a.5.5,0,0,0,.6-.22l2-3.46a.48.48,0,0,0,.11-.62ZM12,15.5A3.5,3.5,0,1,1,15.5,12,3.5,3.5,0,0,1,12,15.5Z" />
            </svg>
          )}
        </button>
      </header>

      <hr className="divider" />

      {showConfig ? (
        <section className="config">
          <h2 className="subtitulo">Configuración</h2>
          <form className="form" onSubmit={handleGuardar}>
            <div className="tabs">
              <button
                type="button"
                className={activeTab === "dms" ? "tab active" : "tab"}
                onClick={() => setActiveTab("dms")}
              >
                Quiter / Star
              </button>

              <button
                type="button"
                className={activeTab === "qae" ? "tab active" : "tab"}
                onClick={() => setActiveTab("qae")}
              >
                QAE
              </button>
              <button
                type="button"
                className={activeTab === "qac" ? "tab active" : "tab"}
                onClick={() => setActiveTab("qac")}
              >
                QAC
              </button>
              <button
              type="button"
              className={activeTab === "api" ? "tab active" : "tab"}
              onClick={() => setActiveTab("api")}
              >
                API
              </button>
            </div>
            {activeTab === "dms" && (
              <>
                <div className="form-group">
                  <label htmlFor="websocketpuerto">Puerto Agente</label>
                  <input
                    id="websocketpuerto"
                    type="number"
                    value={websocketpuerto}
                    onChange={(e) => setWebsocketpuerto(e.target.value)}
                    className="input"
                  />
                </div>

                <div className="form-group">
                  <label>DMS</label>
                  <label>
                    <input
                      type="checkbox"
                      checked={dms.quiter}
                      onChange={() => handleDmsChange("quiter")}
                    />
                    Quiter
                  </label>

                  <label>
                    <input
                      type="checkbox"
                      checked={dms.star}
                      onChange={() => handleDmsChange("star")}
                    />
                    Star
                  </label>
                </div>

                <div className="form-group">
                  <label htmlFor="server">Server</label>
                  <input
                    id="server"
                    type="text"
                    value={server}
                    onChange={(e) => setServer(e.target.value)}
                    className="input"
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="usuario">Usuario</label>
                  <input
                    id="usuario"
                    type="text"
                    value={usuario}
                    onChange={(e) => setUsuario(e.target.value)}
                    className="input"
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="contrasena">Contraseña</label>
                  <input
                    id="contrasena"
                    type="password"
                    value={contrasena}
                    onChange={(e) => setContrasena(e.target.value)}
                    className="input"
                  />
                </div>
              </>
            )}

            {activeTab === "qae" && (
              <>
                <div className="form-group">
                  <label>
                    <input
                      type="checkbox"
                      checked={useQae}
                      onChange={(e) => setUseQae(e.target.checked)}
                    />
                    Usar QAE
                  </label>
                </div>

                <div className="form-group">
                  <label>Servidor QAE</label>
                  <input
                    type="text"
                    value={qaeServer}
                    onChange={(e) => setQaeServer(e.target.value)}
                    disabled={!useQae}
                    className="input"
                  />
                </div>

                <div className="form-group">
                  <label>Puerto QAE</label>
                  <input
                    type="text"
                    value={qaePort}
                    onChange={(e) => setQaePort(e.target.value)}
                    disabled={!useQae}
                    className="input"
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="usuarioqae">Usuario QAE</label>
                  <input
                    id="usuarioqae"
                    type="text"
                    value={usuarioQae}
                    onChange={(e) => setUsuarioQae(e.target.value)}
                    className="input"
                    disabled={!useQae}
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="contrasenaqae">Contraseña QAE</label>
                  <input
                    id="contrasenaqae"
                    type="password"
                    value={contrasenaQae}
                    onChange={(e) => setContrasenaQae(e.target.value)}
                    className="input"
                    disabled={!useQae}
                  />
                </div>
              </>
            )}
            {activeTab === "qac" && (
              <>
                <div className="form-group">
                  <label>
                    <input
                      type="checkbox"
                      checked={useQac}
                      onChange={(e) => setUseQac(e.target.checked)}
                    />
                    Usar QAC
                  </label>
                </div>
                <div className="form-group">
                  <label htmlFor="usuarioqac">Usuario QAC</label>
                  <input
                    id="usuarioqac"
                    type="text"
                    value={usuarioQac}
                    onChange={(e) => setUsuarioQac(e.target.value)}
                    className="input"
                    disabled={!useQac}
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="contrasenaqac">Contraseña QAC</label>
                  <input
                    id="contrasenaqac"
                    type="password"
                    value={contrasenaQac}
                    onChange={(e) => setContrasenaQac(e.target.value)}
                    className="input"
                    disabled={!useQac}
                  />
                </div>
                <div className="mb-3">
                  <button onClick={handleObtenerCredencialesQAC} className="btn btn-primary" disabled={!useQac}>
                    Obtener Credenciales QAC
                  </button>
                </div>
              </>
            )}
            {activeTab === "api" && (
              <>
                <div className="form-group">
                  <label htmlFor="apiurl">Api URL</label>
                  <input
                    id="apiurl"
                    type="text"
                    value={apiUrl}
                    onChange={(e) => setApiUrl(e.target.value)}
                    className="input"
                  />
                </div>
              </>
            )}
            <div className="acciones-form">
              <button type="submit" className="btn btn-primary">
                Guardar
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => setShowConfig(false)}
              >
                Cancelar
              </button>
            </div>
          </form>
        </section>
      ) : (
        <section className="estado">
          <span className="estado__label">Estado:</span>
          <div className="estado__wrap">
            <span
              className="estado__indicador"
              style={{ backgroundColor: colores[estado] }}
              aria-label={etiquetas[estado]}
              title={etiquetas[estado]}
            />
            <span className="estado__texto">{etiquetas[estado]}</span>
          </div>
        </section>
      )}
    </main>
  );
}
