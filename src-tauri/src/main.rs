// Prevents additional console window on Windows in release, DO NOT REMOVE!!
// LA LINEA SIGUIENTE SI ESTA COMENTADA APARECE LA CONSOLA
//#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use aes_gcm::AeadCore;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use bson::Document; // Ensure this is at the top of your file
use config::{Config, File, FileFormat};
use futures_util::io::AsyncReadExt;
use futures_util::io::AsyncWriteExt as FuturesAsyncWriteExt;
use futures_util::stream::TryStreamExt;
use futures_util::StreamExt as _;
use mime_guess::from_path;
use mongodb::bson::{self, from_document, Bson, DateTime};
use mongodb::gridfs::GridFsBucket;
use mongodb::options::FindOneOptions;
use mongodb::options::GridFsBucketOptions;
use mongodb::options::GridFsUploadOptions;
use mongodb::{bson::doc, options::ClientOptions, Client, Collection};
use reqwest; // Se importa para realizar peticiones HTTP
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use tauri::{CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, Duration};

// ============ AÑADIMOS IMPORTS PARA SERVIDOR AXUM ============
use axum::extract::Query;
use axum::{extract::DefaultBodyLimit, routing::post, Router};
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json};
use serde_json::json;

// ─── arriba, junto al resto ────────────────────────────────────────────────────
use chrono::DateTime as ChronoDateTime;
use rusqlite::{params, Connection};

use axum::http::Method;
use tower_http::cors::{Any, CorsLayer};

use tauri::api::path::app_config_dir;

// --- Clave fija para (des)encriptar credenciales (igual que en el otro archivo)
const ENCRYPT_PASSWORD: &str = "#SynergyaTechÑ2024*";

#[tauri::command]
fn obtener_contrasena_encrypt() -> String {
    ENCRYPT_PASSWORD.to_string()
}

fn get_install_config_dir() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    exe_dir.join("config")
}

fn open_db() -> Result<Connection, String> {
    let base_path = get_install_config_dir();

    // Crear carpeta si no existe
    std::fs::create_dir_all(&base_path).map_err(|e| e.to_string())?;

    let db_path = base_path.join("config.db");

    println!("📁 Usando base de datos: {:?}", db_path);

    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS ConfigApp (
            server TEXT,
            username TEXT,
            password TEXT,
            puertoagente TEXT,
            usequiter INTEGER,
            usestar INTEGER,
            ipservidor TEXT
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    Ok(conn)
}

// Reutiliza tus funciones AES-GCM
fn encrypt_local(plain: &str, key: &str) -> Result<String, String> {
    Ok(encrypt(plain, key))
}
fn decrypt_local(enc_b64: &str, key: &str) -> Result<String, String> {
    let key = prepare_key(key);
    let encrypted_data = general_purpose::STANDARD
        .decode(enc_b64)
        .map_err(|_| "Base64 inválido".to_string())?;

    let nonce = Nonce::from_slice(&encrypted_data[..12]);
    let ciphertext = &encrypted_data[12..];

    let cipher = Aes256Gcm::new(&key);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Fallo en la desencriptación".to_string())?;

    String::from_utf8(plaintext).map_err(|_| "UTF-8 inválido".to_string())
}

#[derive(Debug, Serialize, Deserialize)]
struct ConfigRow {
    server: String,
    username: String, // devuelto DESCIFRADO
    password: String, // devuelto DESCIFRADO
    puertoagente: String,
    usequiter: i64,
    usestar: i64,
    ipservidor: String,
}

#[tauri::command]
fn guardar_config_sqlite(
    server: String,
    username: String,
    password: String,
    puertoagente: String,
    usequiter: i64,
    usestar: i64,
    ipservidor: String,
    key: String,
) -> Result<(), String> {
    if key.is_empty() {
        return Err("Clave de cifrado vacía".into());
    }

    let conn = open_db()?;

    // Cifrado antes de persistir
    let username_enc = encrypt_local(&username, &key)?;
    let password_enc = encrypt_local(&password, &key)?;

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM ConfigApp", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;

    if count == 0 {
        conn.execute(
            "INSERT INTO ConfigApp (server, username, password, puertoagente, usequiter, usestar, ipservidor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                server,
                username_enc,
                password_enc,
                puertoagente,
                usequiter,
                usestar,
                ipservidor
            ],
        )
        .map_err(|e| e.to_string())?;
    } else {
        conn.execute(
            "UPDATE ConfigApp SET
                server       = ?1,
                username     = ?2,
                password     = ?3,
                puertoagente = ?4,
                usequiter    = ?5,
                usestar      = ?6,
                ipservidor   = ?7",
            params![
                server,
                username_enc,
                password_enc,
                puertoagente,
                usequiter,
                usestar,
                ipservidor
            ],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn obtener_config_sqlite(key: String) -> Result<ConfigRow, String> {
    let conn = open_db()?;

    let mut stmt = conn
        .prepare(
            "SELECT server, username, password, puertoagente, usequiter, usestar, ipservidor
             FROM ConfigApp
             LIMIT 1",
        )
        .map_err(|e| e.to_string())?;

    let row = stmt.query_row([], |row| {
        Ok((
            row.get::<_, String>(0)?,                    // server
            row.get::<_, String>(1)?,                    // username (cifrado o plano)
            row.get::<_, String>(2)?,                    // password (cifrado o plano)
            row.get::<_, String>(3).unwrap_or_default(), // puertoagente
            row.get::<_, i64>(4).unwrap_or(0),           // usequiter
            row.get::<_, i64>(5).unwrap_or(0),           // usestar
            row.get::<_, String>(6).unwrap_or_default(), // ipservidor
        ))
    });

    match row {
        Ok((server, username_enc, password_enc, puertoagente, usequiter, usestar, ipservidor)) => {
            // Intentamos descifrar; si falla, asumimos que estaba en plano
            let username =
                decrypt_local(&username_enc, &key).unwrap_or_else(|_| username_enc.clone());
            let password =
                decrypt_local(&password_enc, &key).unwrap_or_else(|_| password_enc.clone());
            Ok(ConfigRow {
                server,
                username,
                password,
                puertoagente,
                usequiter,
                usestar,
                ipservidor,
            })
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(ConfigRow {
            server: "".into(),
            username: "".into(),
            password: "".into(),
            puertoagente: "".into(),
            usequiter: 0,
            usestar: 0,
            ipservidor: "".into(),
        }),
        Err(e) => Err(e.to_string()),
    }
}

// ============ COMANDOS DE ENCRIPTACIÓN ============
#[tauri::command]
fn encrypt(plain_text: &str, key: &str) -> String {
    let key = prepare_key(key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; único por mensaje

    let ciphertext = cipher
        .encrypt(&nonce, plain_text.as_bytes().as_ref())
        .expect("Fallo en la encriptación");

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    general_purpose::STANDARD.encode(result)
}

#[tauri::command]
fn decrypt(encrypted_text: &str, key: &str) -> String {
    let key = prepare_key(key);
    let encrypted_data = general_purpose::STANDARD
        .decode(encrypted_text)
        .expect("Fallo base64 decode");

    let nonce = Nonce::from_slice(&encrypted_data[..12]);
    let ciphertext = &encrypted_data[12..];

    let cipher = Aes256Gcm::new(&key);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("Fallo en la desencriptación");

    String::from_utf8(plaintext).expect("UTF-8 inválido")
}

fn prepare_key(key: &str) -> Key<Aes256Gcm> {
    let mut key_bytes = [0u8; 32];
    let key_slice = key.as_bytes();
    let key_len = key_slice.len().min(32);
    key_bytes[..key_len].copy_from_slice(&key_slice[..key_len]);
    Key::<Aes256Gcm>::from_slice(&key_bytes).clone()
}

// Estructura de la Orden
#[derive(Debug, Serialize, Deserialize)]
struct Orden {
    #[serde(rename = "idOrden")]
    id_orden: i64,
    #[serde(rename = "codigo")]
    codigo: String,
    #[serde(rename = "dni")]
    dni: String,
    #[serde(rename = "nombre")]
    nombre: String,
    #[serde(rename = "matricula")]
    matricula: String,
    #[serde(rename = "referenciadms")]
    referenciadms: String,
}

// Función auxiliar para obtener el cliente de MongoDB (implementa esta función según tu configuración)
async fn get_mongo_client() -> Result<mongodb::Client, Box<dyn std::error::Error>> {
    let client_options =
        mongodb::options::ClientOptions::parse("mongodb://localhost:27017").await?;
    Ok(mongodb::Client::with_options(client_options)?)
}

/// Función para buscar órdenes en la colección "ordenes" de la base de datos "business_db"
async fn buscar_orden(
    codigo: Option<String>,
    dni: Option<String>,
    nombre: Option<String>,
) -> Result<Vec<Orden>, String> {
    // Conecta a MongoDB
    let client = get_mongo_client()
        .await
        .map_err(|e| format!("Error conectando a MongoDB: {}", e))?;
    let collection: Collection<Orden> = client.database("business_db").collection("ordenes");

    // Construimos el filtro dinámicamente según los parámetros recibidos
    let mut filter = doc! {};

    if let Some(c) = codigo {
        filter.insert("codigo", c);
    }
    if let Some(d) = dni {
        filter.insert("dni", d);
    }
    if let Some(n) = nombre {
        filter.insert("nombre", n);
    }

    // Ejecutamos la búsqueda en la colección
    let cursor = collection
        .find(filter, None)
        .await
        .map_err(|e| format!("Error al realizar la búsqueda: {}", e))?;

    let ordenes: Vec<Orden> = cursor
        .try_collect()
        .await
        .map_err(|e| format!("Error al procesar los resultados: {}", e))?;
    Ok(ordenes)
}

// --- Definición de la estructura de Documento ---
#[derive(Debug, Serialize, Deserialize)]
struct Documento {
    #[serde(rename = "idDocumento")]
    id_documento: i64,
    #[serde(rename = "idUsuario")]
    id_usuario: i64,
    #[serde(rename = "Carpeta")]
    carpeta: String,
    #[serde(rename = "NombreArchivo")]
    nombre_archivo: String,
    #[serde(rename = "tipo_archivo")]
    tipo_archivo: Option<String>,
    #[serde(rename = "Mimetype")]
    mimetype: Option<String>,
    #[serde(rename = "FicheroDMS")]
    fichero_dms: Option<String>,
    #[serde(rename = "ReferenciaDMS")]
    referencia_dms: Option<String>,
    #[serde(rename = "UsuarioDMS")]
    usuario_dms: Option<String>,
    #[serde(rename = "FechaUltimaModificacion")]
    fecha_ultima_modificacion: Option<i64>,
    #[serde(rename = "idOrden")]
    id_orden: Option<i64>,
    #[serde(rename = "idVehiculo")]
    id_vehiculo: Option<i64>,
    #[serde(rename = "id_cliente")]
    id_cliente: Option<i64>,
    #[serde(rename = "tamano_archivo")]
    tamano_archivo: i64,
    // Otros campos según sea necesario
}

// --- Función para detectar el tipo de archivo ---
fn detectar_tipo_archivo(nombre_archivo: &str) -> Option<String> {
    Path::new(nombre_archivo)
        .extension()
        .and_then(|os_str| os_str.to_str())
        .map(|ext| ext.to_lowercase())
}

fn detectar_mimetype(nombre_archivo: &str) -> Option<String> {
    from_path(nombre_archivo).first_raw().map(|s| s.to_string())
}

// Función para obtener el idOrden basado en la referencia (por ejemplo, "ReferenciaDMS")
async fn obtener_id_orden_por_referencia(
    client: &mongodb::Client,
    referencia: &str,
) -> Result<Option<i64>, String> {
    use futures::stream::TryStreamExt;
    use mongodb::bson::doc;

    // Accedemos a la colección "ordenes"
    let ordenes_collection = client
        .database("business_db")
        .collection::<mongodb::bson::Document>("ordenes");

    // Ajustamos el filtro: usamos el nombre de campo "referenciadms" tal y como aparece en la base de datos.
    let filter = doc! { "referenciadms": referencia };

    let orden_doc = ordenes_collection
        .find_one(filter.clone(), None)
        .await
        .map_err(|e| e.to_string())?;

    println!("Filtro aplicado: {:?}", filter);
    println!("Documento encontrado: {:?}", orden_doc);

    if let Some(doc) = orden_doc {
        // Extraemos el idOrden; en el ejemplo, se espera que esté almacenado como un entero
        // Si get_i64 falla, se puede utilizar as_i64(), por ejemplo:
        if let Some(id_orden) = doc.get("idOrden").and_then(|v| v.as_i64()) {
            Ok(Some(id_orden))
        } else {
            Err("El documento encontrado no contiene un idOrden válido".into())
        }
    } else {
        Ok(None)
    }
}

// --- Función para insertar un documento ---
#[tauri::command]
async fn insertar_documento(
    id_usuario: i64,
    carpeta: String,
    nombre_archivo: String,
    tipo_archivo: Option<String>,
    mimetype: Option<String>,
    fichero_dms: Option<String>,
    referencia_dms: Option<String>,
    usuario_dms: Option<String>,
    fecha_ultima_modificacion: Option<i64>,
    id_orden: Option<i64>, // Este valor será reemplazado, según la referencia
    id_vehiculo: Option<i64>,
    id_cliente: Option<i64>,
    file: Vec<u8>,
    tamano_archivo: i64,
) -> Result<(), String> {
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;

    // Si se envía una referencia para la orden, se consulta la colección "ordenes" para extraer el idOrden correspondiente.
    let id_orden_final = if let Some(ref referencia) = referencia_dms {
        obtener_id_orden_por_referencia(&client, referencia).await?
    } else {
        None
    };

    // Accedemos a la colección "documentos.files"
    let files_collection = client
        .database("business_db")
        .collection::<Document>("documentos.files");

    // Obtener nuevo idDocumento para el GridFS (se mantiene tu lógica actual)
    let last_document = files_collection
        .aggregate(
            vec![
                doc! { "$unwind": "$metadata" },
                doc! { "$sort": { "metadata.idDocumento": -1 } },
                doc! { "$limit": 1 },
            ],
            None,
        )
        .await
        .map_err(|e| e.to_string())?
        .try_next()
        .await
        .map_err(|e| e.to_string())?;

    let nuevo_id_documento = match last_document {
        Some(doc) => {
            let metadata = doc.get_document("metadata").map_err(|e| e.to_string())?;
            metadata
                .get_i64("idDocumento")
                .map(|id| id + 1)
                .unwrap_or(1)
        }
        None => 1,
    };

    let fecha_modificacion = fecha_ultima_modificacion.map(|ts| DateTime::from_millis(ts));

    let database = client.database("business_db");
    let bucket = database.gridfs_bucket(Some(
        GridFsBucketOptions::builder()
            .bucket_name(Some("documentos".to_string()))
            .chunk_size_bytes(1048576)
            .build(),
    ));

    let descripcion = format!("Fichero {}", nombre_archivo);

    // Detectamos el tipo de archivo usando la función que extrae la extensión
    let tipo_final = detectar_tipo_archivo(&nombre_archivo).or(tipo_archivo);

    // Opcional: Obtener mimetype automáticamente (usando mime_guess u otra lógica)
    let mimetype_final = mimetype.or_else(|| detectar_mimetype(&nombre_archivo));

    let metadata = doc! {
        "idDocumento": nuevo_id_documento,
        "idUsuario": id_usuario,
        "Carpeta": carpeta,
        "NombreArchivo": nombre_archivo.clone(),
        "tipo_archivo": tipo_final,
        "Mimetype": mimetype_final,
        "FicheroDMS": fichero_dms,
        "ReferenciaDMS": referencia_dms,
        "UsuarioDMS": usuario_dms,
        "FechaUltimaModificacion": fecha_modificacion,
        "idOrden": id_orden_final,  // Aquí se asigna la idOrden obtenida de la colección "ordenes"
        "idVehiculo": id_vehiculo,
        "id_cliente": id_cliente,
        "tamano_archivo": tamano_archivo,
        "descripcion": descripcion,
    };

    let upload_options = GridFsUploadOptions::builder().metadata(metadata).build();

    let mut upload_stream = bucket.open_upload_stream(nombre_archivo.clone(), upload_options);
    upload_stream
        .write_all(&file)
        .await
        .map_err(|e| e.to_string())?;
    upload_stream.close().await.map_err(|e| e.to_string())?;

    Ok(())
}

// --- Definición del payload para insertar documento ---
#[derive(Debug, Serialize, Deserialize)]
struct InsertarDocumentoPayload {
    id_usuario: i64,
    carpeta: String,
    nombre_archivo: String,
    tipo_archivo: Option<String>,
    mimetype: Option<String>,
    fichero_dms: Option<String>,
    referencia_dms: Option<String>,
    usuario_dms: Option<String>,
    fecha_ultima_modificacion: Option<i64>,
    id_orden: Option<i64>,
    id_vehiculo: Option<i64>,
    id_cliente: Option<i64>,
    // Recibiremos el archivo como cadena Base64 y lo decodificaremos a Vec<u8>
    file: String,
    tamano_archivo: i64,
}

// --- Handler para el endpoint de insertar documento ---
async fn insertar_documento_handler(
    Json(payload): Json<InsertarDocumentoPayload>,
) -> impl IntoResponse {
    // Decodificar el archivo recibido (Base64 -> Vec<u8>)
    let file_bytes = match base64::decode(&payload.file) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
        }
    };

    match insertar_documento(
        payload.id_usuario,
        payload.carpeta,
        payload.nombre_archivo,
        payload.tipo_archivo,
        payload.mimetype,
        payload.fichero_dms,
        payload.referencia_dms,
        payload.usuario_dms,
        payload.fecha_ultima_modificacion,
        payload.id_orden,
        payload.id_vehiculo,
        payload.id_cliente,
        file_bytes,
        payload.tamano_archivo,
    )
    .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "status": "Documento insertado correctamente" })),
        ),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

#[derive(Debug, Deserialize)]
struct BuscarOrdenParams {
    orden: Option<String>,
    matricula: Option<String>,
    codigo: Option<String>,
    dni: Option<String>,
    nombre: Option<String>,
}

async fn buscar_orden_backend(
    State(backend): State<Arc<Mutex<PythonBackend>>>,
    Query(params): Query<BuscarOrdenParams>,
) -> impl IntoResponse {
    let comando = serde_json::json!({
        "comando": "buscarOrdenes",
        "orden":     params.orden.unwrap_or_default(),
        "matricula": params.matricula.unwrap_or_default(),
        "codigo":    params.codigo.unwrap_or_default(),
        "dni":       params.dni.unwrap_or_default(),
        "nombre":    params.nombre.unwrap_or_default()
    });

    let resp = {
        let mut bk = backend.lock().unwrap();
        bk.send_command(&comando.to_string())
    };

    match serde_json::from_str::<serde_json::Value>(&resp) {
        /* error JSON → 400 y devolvemos el mismo texto */
        Ok(json) if json.get("error").is_some() => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": json["error"] })),
        )
            .into_response(),
        /* éxito JSON → 200 */
        Ok(json) => (StatusCode::OK, Json(json)).into_response(),
        /* respuesta no‑JSON → consideramos error puro */
        Err(_) => (StatusCode::BAD_REQUEST, Json(json!({ "error": resp }))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct OrdenQuery {
    codigo: Option<String>,
    dni: Option<String>,
    nombre: Option<String>,
}

// Handler que recibe la query, invoca a `buscar_orden` y devuelve el resultado.
async fn buscar_orden_handler(Query(mut query): Query<OrdenQuery>) -> impl IntoResponse {
    // Si no se recibe un código, lo asignamos por defecto a "1410"
    if query.codigo.is_none() {
        query.codigo = Some("1410".to_string());
    }

    match buscar_orden(query.codigo, query.dni, query.nombre).await {
        Ok(ordenes) => (StatusCode::OK, Json(json!({ "result": ordenes }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

// ============ MANEJO DE ARCHIVOS INI ============
async fn create_uopy_ini() {
    let ini_content = r#"
[logging]
level = 50
dir = './.logs'
file_name = 'critical.log'
backup_count = 0
log_data_max_size = 0
"#;

    let mut file = fs::File::create("uopy.ini")
        .await
        .expect("No se pudo crear uopy.ini");
    file.write_all(ini_content.as_bytes())
        .await
        .expect("No se pudo escribir en uopy.ini");
}

async fn delete_uopy_ini() {
    // Pausa breve para asegurar que el backend terminó de inicializar
    sleep(Duration::from_secs(3)).await;
    fs::remove_file("uopy.ini")
        .await
        .expect("No se pudo eliminar uopy.ini");
}

// ============ BACKEND PYTHON (O DLL) ============
struct PythonBackend {
    stdin: std::process::ChildStdin,
    stdout: Arc<Mutex<BufReader<std::process::ChildStdout>>>,
}

impl PythonBackend {
    fn new(_app_handle: &tauri::AppHandle) -> Self {
        let app_path = env::current_exe()
            .ok()
            .and_then(|exe_path| exe_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));

        let system32_path = env::var("SystemRoot")
            .map(|system_root| PathBuf::from(system_root).join("System32"))
            .unwrap_or_else(|_| app_path.clone());

        let backend_path = [system32_path, app_path]
            .iter()
            .map(|path| path.join("brcom.dll"))
            .find(|path| path.exists())
            .expect("brcom.dll no encontrado en ninguna de las rutas.");

        println!("Backend path: {:?}", backend_path);

        let mut child = Command::new(&backend_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "Fallo al iniciar proceso: {:?}\nRuta probada: {:?}",
                    e, backend_path
                )
            });

        let stdin = child.stdin.take().expect("No se pudo abrir stdin");
        let stdout = BufReader::new(child.stdout.take().expect("No se pudo abrir stdout"));

        PythonBackend {
            stdin,
            stdout: Arc::new(Mutex::new(stdout)),
        }
    }

    fn send_command(&mut self, input: &str) -> String {
        writeln!(self.stdin, "{}", input).expect("Fallo al escribir en stdin");

        let mut response = String::new();
        self.stdout
            .lock()
            .unwrap()
            .read_line(&mut response)
            .expect("Fallo al leer stdout");
        response.trim().to_string()
    }
}

#[tauri::command]
async fn api_command_py(
    input_json: String,
    state: tauri::State<'_, Arc<Mutex<PythonBackend>>>,
) -> Result<String, String> {
    let mut backend = state.lock().unwrap();
    let response = backend.send_command(&input_json);

    // Intentamos parsear la respuesta por si es un string escapado
    let unescaped_response = match serde_json::from_str::<Value>(&response) {
        Ok(Value::String(s)) => s,
        _ => response,
    };

    // Intentamos parsearlo como JSON. Si falla, enviamos un error genérico
    match serde_json::from_str::<serde_json::Value>(&unescaped_response) {
        Ok(_) => Ok(unescaped_response),
        Err(_) => Ok(serde_json::json!({
            "error": "Respuesta inválida del backend"
        })
        .to_string()),
    }
}

// ============ NUEVO: LLAMADA A LA API CON ID PREDEFINIDO ============
async fn call_api_cargar_doc_ordenes(backend: Arc<Mutex<PythonBackend>>) -> Result<String, String> {
    let id = "663b5ebb5f93a70f3402cd88";
    let parametros = serde_json::json!({
        "comando": "cargarDocOrdenes",
        "id": id,
    });
    let parametros_string = parametros.to_string();

    let mut backend_lock = backend.lock().unwrap();
    let response = backend_lock.send_command(&parametros_string);

    let unescaped_response = match serde_json::from_str::<Value>(&response) {
        Ok(Value::String(s)) => s,
        _ => response,
    };

    match serde_json::from_str::<serde_json::Value>(&unescaped_response) {
        Ok(json_value) => {
            if let Some(error) = json_value.get("error") {
                Err(error.to_string())
            } else if let Some(result) = json_value.get("result") {
                let mut base64_string = result.as_str().unwrap_or("").to_string();

                if base64_string.starts_with("b'") {
                    base64_string = base64_string.trim_start_matches("b'").to_string();
                }
                if base64_string.ends_with('\'') {
                    base64_string = base64_string.trim_end_matches('\'').to_string();
                }
                Ok(base64_string)
            } else {
                Err("Respuesta no contiene el campo 'result'.".into())
            }
        }
        Err(_) => Err("Respuesta inválida del backend.".into()),
    }
}

#[tauri::command]
async fn call_api_cargar_doc_ordenes_backend(
    state: tauri::State<'_, Arc<Mutex<PythonBackend>>>,
) -> Result<String, String> {
    call_api_cargar_doc_ordenes(state.inner().clone()).await
}

// ============ NUEVO: COMANDO PARA LLAMAR AL STATUS DEL SERVIDOR EXPRESS ============
#[tauri::command]
async fn call_express_status() -> Result<String, String> {
    // Asegúrate de que la URL coincida con la ruta definida en tu server.js
    let express_status_url = "http://192.168.1.156:3000/api/status";

    let response = reqwest::get(express_status_url)
        .await
        .map_err(|e| format!("Error en la conexión: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Error: estado HTTP {}", response.status()));
    }

    let json_response: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Error al parsear JSON: {}", e))?;

    Ok(format!("Express status: {}", json_response))
}

// ============ ENDPOINTS PARA LA APP MÓVIL ============
#[derive(Debug, Serialize, Deserialize)]
struct ApiRequest {
    command: String,
    data: Option<serde_json::Value>,
}

async fn api_handler(
    State(backend): State<Arc<Mutex<PythonBackend>>>,
    Json(payload): Json<ApiRequest>,
) -> impl IntoResponse {
    println!("[api_handler] Payload recibido del cliente:");
    println!("  command: {}", payload.command);
    println!(
        "  data: {}",
        payload
            .data
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "null".to_string())
    );

    println!(
        "[api_handler] Enviando al backend Python/DLL: {}",
        payload.command
    );
    let mut backend = backend.lock().unwrap();
    let response = backend.send_command(&payload.command);

    println!("[api_handler] Respuesta cruda recibida del backend:");
    println!("  {}", response);

    // 🔹 4) Intentar parsear y responder al cliente
    match serde_json::from_str::<serde_json::Value>(&response) {
        Ok(json_response) => {
            println!("[api_handler] Respuesta parseada como JSON OK");
            (StatusCode::OK, Json(json_response)).into_response()
        }
        Err(_) => {
            println!("[api_handler] Respuesta NO es JSON válido, devolviendo crudo");
            (
                StatusCode::OK,
                Json(serde_json::json!({ "response": response })),
            )
                .into_response()
        }
    }
}

async fn status_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "message": "Conector de rust a frontend funcionando correctamente"
        })),
    )
        .into_response()
}

async fn test_call_backend(backend: Arc<Mutex<PythonBackend>>) {
    let test_data = serde_json::json!({
        "comando": "consultaCampanaSTAR",
        "SQL": "SELECT * FROM TBL_ProductionOrderRegistry WHERE TRY_CAST(TBL_ProductionOrderRegistry.FLD_DailyCloseDate AS date) BETWEEN '2022-02-08' AND '2022-12-31'"
    });

    let input_json = test_data.to_string();

    println!("[TEST] Enviando al backend:\n{}", input_json);

    let mut backend = backend.lock().unwrap();
    let response = backend.send_command(&input_json);

    println!("[TEST] Respuesta recibida:\n{}", response);
}

#[derive(Debug, serde::Deserialize)]
struct SubirDocOrdenesPayload {
    #[serde(rename = "fileByte")]
    file_byte: String,
    filename: String,
    mimetype: String,
    #[serde(rename = "referenciaDMS")]
    referencia_dms: Option<String>,
    #[serde(rename = "usuarioDMS")]
    usuario_dms: Option<String>,
    ultimafecha: String,
    // (opcional) si el front lo manda; si no, lo calculamos
    tamano_archivo: Option<i64>,
}

// ============ MAIN TAURI ============
#[tokio::main]
async fn main() {
    // 1) Creamos uopy.ini antes de iniciar
    create_uopy_ini().await;

    let config_path = get_install_config_dir().join("config.cfg");

    // Convertir Cow<'_, str> → String → &str
    let config_path_str = config_path.to_string_lossy().to_string();

    let settings = Config::builder()
        .add_source(File::new(&config_path_str, FileFormat::Ini).required(true))
        .build()
        .expect("No se pudo leer config.cfg");

    let port: u16 = settings.get::<u16>("appSettings.port").unwrap_or(8080);

    // 4) Definimos el menú del system tray
    let quit = CustomMenuItem::new("quit".to_string(), "Salir");
    let config = CustomMenuItem::new("config".to_string(), "Estado");
    let tray_menu = SystemTrayMenu::new().add_item(config).add_item(quit);
    let tray = SystemTray::new().with_menu(tray_menu);

    tauri::Builder::default()
        .system_tray(tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "quit" => {
                    std::process::exit(0);
                }
                "config" => {
                    if let Some(window) = app.get_window("main") {
                        window.show().unwrap();
                        window.set_focus().unwrap();
                    }
                }
                _ => {}
            },
            _ => {}
        })
        .on_window_event(|event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event.event() {
                event.window().hide().unwrap();
                api.prevent_close();
            }
        })
        // Capturamos `port` por valor para usarlo más abajo
        .setup(move |app| {
            let app_handle = app.handle();

            // Inicializamos el backend
            let python_backend = Arc::new(Mutex::new(PythonBackend::new(&app_handle)));
            app.manage(python_backend.clone());

            // === TEST: consultaCampanaSTAR ===
            let backend_test = python_backend.clone();
            tauri::async_runtime::spawn(async move {
                test_call_backend(backend_test).await;
            });

            // Programamos la eliminación de uopy.ini tras 3 segundos
            tauri::async_runtime::spawn(async {
                delete_uopy_ini().await;
            });

            // Iniciar servidor AXUM...
            let backend_clone = python_backend.clone();
            tauri::async_runtime::spawn({
                let port = port;
                async move {
                    let cors = CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods([Method::GET])
                        .allow_headers(Any);

                    let router = Router::new()
                        .route("/ordenes", get(buscar_orden_handler))
                        .route("/buscar_orden", get(buscar_orden_backend))
                        .route("/api", post(api_handler))
                        .route("/status", get(status_handler))
                        .route("/insertarDocumento", post(insertar_documento_handler))
                        .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
                        .layer(cors)
                        .with_state(backend_clone);

                    let addr = SocketAddr::from(([0, 0, 0, 0], port));
                    println!("Servidor corriendo en http://{}", addr);

                    if let Err(e) = axum::Server::bind(&addr)
                        .serve(router.into_make_service())
                        .await
                    {
                        eprintln!("Axum-error: {e}");
                    }
                }
            });

            // Llamada inicial a cargarDocOrdenes
            let backend_for_call = python_backend.clone();
            tauri::async_runtime::spawn(async move {
                match call_api_cargar_doc_ordenes(backend_for_call).await {
                    Ok(result) => println!(""),
                    Err(err) => println!(""),
                }
            });

            if let Some(window) = app.get_window("main") {
                window.hide().unwrap();
            }

            #[cfg(debug_assertions)]
            {
                let window = app.get_window("main").unwrap();
                window.open_devtools();
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            api_command_py,
            encrypt,
            decrypt,
            call_api_cargar_doc_ordenes_backend,
            call_express_status,
            guardar_config_sqlite,
            obtener_config_sqlite,
            obtener_contrasena_encrypt,
        ])
        .run(tauri::generate_context!())
        .expect("Error al ejecutar la aplicación Tauri");
}
