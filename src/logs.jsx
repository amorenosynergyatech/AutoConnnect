import { useEffect, useState } from "react";
import { readTextFile } from "@tauri-apps/api/fs";
import { getCurrent } from "@tauri-apps/api/window";

export default function Logs() {
    const [contenido, setContenido] = useState("Cargando logs...");
    const [loading, setLoading] = useState(true);

    async function cargarLogs() {
        try {
            const data = await readTextFile("critical.log");
            setContenido(data || "El archivo de logs está vacío.");
        } catch (e) {
            setContenido("❌ No se pudo leer el archivo de logs.");
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => {
        cargarLogs();
    }, []);

    useEffect(() => {
        cargarLogs();
        const interval = setInterval(cargarLogs, 1000); // cada 3 segundos
        return () => clearInterval(interval);
    }, []);


    return (
        <div
            style={{
                background: "linear-gradient(135deg, #1a1a1a, #121212)",
                color: "#eaeaea",
                height: "100vh",
                padding: "30px",
                fontFamily: "'Fira Code', monospace",
                display: "flex",
                flexDirection: "column",
            }}
        >
            <h1 style={{ fontSize: "1.8rem", color: "#00ff9f", marginBottom: "20px" }}>
                🧾 Logs de la aplicación
            </h1>

            <div
                style={{
                    flex: 1,
                    backgroundColor: "#0d0d0d",
                    border: "1px solid #222",
                    borderRadius: "10px",
                    padding: "15px",
                    overflowY: "auto",
                    boxShadow: "0 0 10px rgba(0,0,0,0.3)",
                    whiteSpace: "pre-wrap",
                    fontSize: "0.9rem",
                    color: "#aaffaa",
                }}
            >
                {loading ? "Cargando logs..." : contenido}
            </div>

            <div style={{ textAlign: "right", marginTop: "20px" }}>
                <button
                    onClick={() => getCurrent().hide()}
                    style={{
                        backgroundColor: "#00ff9f",
                        border: "none",
                        color: "#000",
                        padding: "10px 20px",
                        fontWeight: "bold",
                        borderRadius: "8px",
                        cursor: "pointer",
                        transition: "all 0.2s ease-in-out",
                    }}
                    onMouseOver={(e) => (e.target.style.backgroundColor = "#00d48a")}
                    onMouseOut={(e) => (e.target.style.backgroundColor = "#00ff9f")}
                >
                    Cerrar
                </button>
            </div>
        </div>
    );
}
