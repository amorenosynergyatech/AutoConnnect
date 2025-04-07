// Prevents additional console window on Windows in release, DO NOT REMOVE!! LA LINEA SIGUIENTE SI ESTA COMENTADA APARECE LA CONSOLA
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use aes_gcm::AeadCore;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use bson::Document; // Ensure this is at the top of your file
use futures_util::io::AsyncReadExt;
use futures_util::io::AsyncWriteExt as FuturesAsyncWriteExt; // Importar para cerrar el flujo
use futures_util::stream::TryStreamExt;
use futures_util::StreamExt as _;
// Importar TryStreamExt para try_collect
use config::{Config, File, FileFormat};
use mongodb::bson::{self, from_document, Bson, DateTime};
use mongodb::options::FindOneOptions;
use mongodb::options::GridFsBucketOptions;
use mongodb::options::GridFsUploadOptions;
use mongodb::{bson::doc, options::ClientOptions, Client, Collection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use tauri::Manager;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, Duration};

#[tauri::command]
fn encrypt(plain_text: &str, key: &str) -> String {
    let key = prepare_key(key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = cipher
        .encrypt(&nonce, plain_text.as_bytes().as_ref())
        .expect("encryption failure!");

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    general_purpose::STANDARD.encode(result)
}

#[tauri::command]
fn decrypt(encrypted_text: &str, key: &str) -> String {
    let key = prepare_key(key);
    let encrypted_data = general_purpose::STANDARD
        .decode(encrypted_text)
        .expect("base64 decoding failure!");

    let nonce = Nonce::from_slice(&encrypted_data[..12]);
    let ciphertext = &encrypted_data[12..];

    let cipher = Aes256Gcm::new(&key);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!");

    String::from_utf8(plaintext).expect("invalid utf-8")
}

fn prepare_key(key: &str) -> Key<Aes256Gcm> {
    let mut key_bytes = [0u8; 32];
    let key_slice = key.as_bytes();
    let key_len = key_slice.len().min(32);
    key_bytes[..key_len].copy_from_slice(&key_slice[..key_len]);
    Key::<Aes256Gcm>::from_slice(&key_bytes).clone()
}

async fn get_mongo_client() -> Result<Client, Box<dyn Error>> {
    // Obtener los datos globales de configuración
    let datos_globales = obtener_datos_globales();

    // Comprobar si se usa QAE o MongoDB estándar
    let (server, port, user, password) = if datos_globales.use_qae {
        // Usar valores predeterminados si `qae_user` o `qae_password` están vacíos
        let user = if datos_globales.qae_user.is_empty() {
            "admin".to_string()
        } else {
            datos_globales.qae_user.clone()
        };

        let password = if datos_globales.qae_password.is_empty() {
            "100495".to_string()
        } else {
            datos_globales.qae_password.clone()
        };

        (
            datos_globales.qae_server.clone(),
            datos_globales.qae_port.clone(),
            user,
            password,
        )
    } else {
        (
            datos_globales.mongodb_server.clone(),
            datos_globales.mongodb_port.clone(),
            datos_globales.mongodb_user.clone(),
            datos_globales.mongodb_password.clone(),
        )
    };

    println!("Usuario antes de descifrar: {}", user);
    println!("Contraseña antes de descifrar: {}", password);

    // Descifrar usuario y contraseña si están encriptados
    let decrypted_user = if !user.is_empty() {
        decrypt(&user, ENCRYPT_PASSWORD)
    } else {
        String::new()
    };

    let decrypted_password = if !password.is_empty() {
        decrypt(&password, ENCRYPT_PASSWORD)
    } else {
        String::new()
    };

    // Usar valores predeterminados si el servidor o puerto están vacíos
    let server = if server.is_empty() {
        "localhost".to_string()
    } else {
        server
    };
    let port = if port.is_empty() {
        "27017".to_string()
    } else {
        port
    };

    println!(
        "Conectando a MongoDB en servidor: {}, puerto: {}",
        server, port
    );

    println!("Usuario descifrado: {}", decrypted_user);
    println!("Contraseña descifrada: {}", decrypted_password);

    // Construir la URI de MongoDB con los mismos parámetros que en MongoDB Compass
    let mongo_uri = if !decrypted_user.is_empty() && !decrypted_password.is_empty() {
        println!("Autenticación detectada. Usuario: {}", decrypted_user);
        format!(
            "mongodb://{}:{}@{}:{}/?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&directConnection=true&ssl=false",
            decrypted_user, decrypted_password, server, port
        )
    } else {
        println!("Conexión sin autenticación.");
        format!(
            "mongodb://{}:{}/?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&directConnection=true&ssl=false",
            server, port
        )
    };

    // Mostrar la URI construida
    println!("MongoDB URI construida: {}", mongo_uri);

    // Crear cliente MongoDB con manejo detallado de errores
    match Client::with_uri_str(&mongo_uri).await {
        Ok(client) => {
            println!("Cliente MongoDB creado exitosamente.");
            Ok(client)
        }
        Err(e) => {
            eprintln!("Error al crear el cliente MongoDB: {:?}", e);
            Err(Box::new(e))
        }
    }
}

#[tauri::command]
async fn verificar_conexion_mongodb() -> Result<String, String> {
    println!("Intentando obtener el cliente de MongoDB...");

    // Intenta obtener el cliente de MongoDB
    let client = match get_mongo_client().await {
        Ok(client) => {
            println!("Cliente de MongoDB obtenido exitosamente.");
            client
        }
        Err(e) => {
            println!("Error al obtener el cliente de MongoDB: {}", e);
            return Err(e.to_string());
        }
    };

    println!("Intentando hacer ping a la base de datos...");

    // Intentar hacer un ping a la base de datos para verificar la conexión
    match client
        .database("quiter-qae")
        .run_command(doc! { "ping": 1 }, None)
        .await
    {
        Ok(_) => {
            println!("Ping exitoso. Conexión a MongoDB verificada.");
            Ok("Conexión a MongoDB exitosa.".to_string())
        }
        Err(e) => {
            println!("Error al hacer ping a la base de datos: {}", e);
            Err(format!("Error al conectar a MongoDB: {}", e))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Vehiculo {
    #[serde(rename = "idVehiculo")]
    id_vehiculo: i64,
    #[serde(rename = "matricula")]
    matricula: String,
    #[serde(rename = "codigo")]
    codigo: String, // Cambio de 'codigo_cliente' a 'codigo'
    #[serde(rename = "dni")]
    dni: String,
    #[serde(rename = "nombre")]
    nombre: String,
}

#[tauri::command]
async fn buscar_vehiculo(
    matricula: Option<String>,
    codigo: Option<String>, // Cambio de 'codigo_cliente' a 'codigo'
    dni: Option<String>,
    nombre: Option<String>,
) -> Result<Vec<Vehiculo>, String> {
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;
    let collection: Collection<Vehiculo> = client.database("business_db").collection("vehiculos");

    let mut filter = doc! {};

    if let Some(m) = matricula {
        filter.insert("matricula", m);
    }
    if let Some(c) = codigo {
        filter.insert("codigo", c); // Cambio de 'codigoCliente' a 'codigo'
    }
    if let Some(d) = dni {
        filter.insert("dni", d);
    }
    if let Some(n) = nombre {
        filter.insert("nombre", n);
    }

    let cursor = collection
        .find(filter, None)
        .await
        .map_err(|e| e.to_string())?;
    let vehiculos: Vec<Vehiculo> = cursor.try_collect().await.map_err(|e| e.to_string())?;

    Ok(vehiculos)
}

#[tauri::command]
async fn insertar_vehiculo(
    matricula: String,
    codigo: String, // Cambio de 'codigo_cliente' a 'codigo'
    dni: String,
    nombre: String,
) -> Result<i64, String> {
    let client = get_mongo_client().await.map_err(|e| {
        println!("Error conectando a MongoDB: {}", e);
        e.to_string()
    })?;

    let collection: Collection<Vehiculo> = client.database("business_db").collection("vehiculos");

    // Verificar si el vehículo ya existe
    let filter = doc! {
        "matricula": &matricula,  // Buscar por matrícula del vehículo
    };

    let existing_vehicle: Option<Vehiculo> = collection
        .find_one(filter, None)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(existing_vehicle) = existing_vehicle {
        println!("El vehículo ya existe: {:?}", existing_vehicle);
        // Si ya existe un vehículo con esa matrícula, retornamos el idVehiculo existente
        return Ok(existing_vehicle.id_vehiculo);
    }

    // Obtener el último vehículo para generar un nuevo id autoincremental
    let last_vehicle: Option<Vehiculo> = collection
        .find_one(
            None,
            FindOneOptions::builder()
                .sort(doc! { "idVehiculo": -1 })
                .build(),
        )
        .await
        .map_err(|e| e.to_string())?;

    let new_id_vehiculo = match last_vehicle {
        Some(vehiculo) => vehiculo.id_vehiculo + 1, // Incrementa el idVehiculo más alto encontrado
        None => 1,                                  // Si no hay vehículos, empezamos con 1
    };

    // Crear un nuevo vehículo
    let nuevo_vehiculo = Vehiculo {
        id_vehiculo: new_id_vehiculo,
        matricula: matricula.clone(),
        codigo: codigo.clone(), // Guardamos el código
        dni,
        nombre,
    };

    println!("Insertando nuevo vehículo: {:?}", nuevo_vehiculo);

    // Insertar el nuevo vehículo en la colección
    let insert_result = collection
        .insert_one(nuevo_vehiculo, None)
        .await
        .map_err(|e| e.to_string())?;

    println!("Resultado de la inserción: {:?}", insert_result);

    // Retornar el nuevo idVehiculo
    Ok(new_id_vehiculo)
}

#[tauri::command]
async fn buscar_documentos_por_vehiculo(id_vehiculo: i64) -> Result<Vec<Document>, String> {
    // Obtener el cliente de MongoDB
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;

    // Conexión a la colección de documentos
    let collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.files");

    // Crear un filtro para obtener documentos por id_orden en metadata
    let filter = doc! { "metadata.idVehiculo": id_vehiculo };

    // Buscar los documentos que coinciden con el filtro
    let mut cursor = collection
        .find(filter, None)
        .await
        .map_err(|e| e.to_string())?;

    // Recopilar los resultados
    let mut resultados = Vec::new();
    while let Some(doc) = cursor.try_next().await.map_err(|e| e.to_string())? {
        // Extraer el nombre del archivo
        if let Some(nombre_archivo) = doc.get("filename").and_then(|f| f.as_str()) {
            // Detectar el tipo de archivo
            if let Some(tipo_archivo) = detectar_tipo_archivo(nombre_archivo) {
                // Agregar el tipo de archivo al documento
                let mut doc = doc.clone();
                doc.insert("tipo_archivo", tipo_archivo);
                resultados.push(doc);
            } else {
                // Si no se detecta el tipo de archivo, se puede manejar de otra manera
                resultados.push(doc);
            }
        } else {
            resultados.push(doc); // Si no tiene filename, igual lo agregamos a los resultados
        }
    }

    Ok(resultados)
}

#[tauri::command]
async fn buscar_documentos_por_criterio_vehiculo(
    id_vehiculo: i64,
    criterio: String,
    tipo_archivo: Option<String>,
    fecha_inicio: Option<String>,
    fecha_fin: Option<String>,
) -> Result<Vec<Document>, String> {
    // Obtener el cliente de MongoDB
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;
    let documentos_collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.files");

    // Crear condiciones de filtro
    let mut filter_conditions = vec![doc! { "metadata.idVehiculo": id_vehiculo }];
    println!("ID Vehículo recibido: {}", id_vehiculo);

    // Agregar condiciones de búsqueda si se proporciona un criterio
    if !criterio.is_empty() {
        println!("Criterio recibido: {}", criterio);
        filter_conditions.push(doc! {
            "$or": [
                { "filename": { "$regex": &criterio, "$options": "i" } },
                { "metadata.Carpeta": { "$regex": &criterio, "$options": "i" } },
                { "metadata.NombreArchivo": { "$regex": &criterio, "$options": "i" } },
                { "metadata.idDocumento": { "$regex": &criterio, "$options": "i" } },
            ]
        });
    }

    // Agregar condición de tipo de archivo si se proporciona
    if let Some(tipo) = &tipo_archivo {
        if !tipo.is_empty() {
            println!("Tipo de archivo recibido: {}", tipo);
            filter_conditions.push(doc! {
                "metadata.tipo_archivo": { "$regex": tipo, "$options": "i" }
            });
        }
    }

    // Agregar condición de rango de fechas si se proporciona al menos una fecha
    if fecha_inicio.is_some() || fecha_fin.is_some() {
        let mut date_conditions = doc! {};
        println!(
            "Rango de fechas - Inicio: {:?}, Fin: {:?}",
            fecha_inicio, fecha_fin
        );

        if let Some(fecha_ini) = &fecha_inicio {
            let fecha_inicio_dt =
                DateTime::parse_rfc3339_str(&fecha_ini).map_err(|e| e.to_string())?;
            date_conditions.insert("$gte", fecha_inicio_dt);
        }

        if let Some(fecha_fin) = &fecha_fin {
            let fecha_fin_dt =
                DateTime::parse_rfc3339_str(&fecha_fin).map_err(|e| e.to_string())?;
            date_conditions.insert("$lte", fecha_fin_dt);
        }

        filter_conditions.push(doc! {
            "metadata.FechaUltimaModificacion": date_conditions
        });
    }

    // Construir el filtro final combinando todas las condiciones
    let filter_documentos = doc! { "$and": filter_conditions };
    println!("Condiciones de filtro aplicadas: {:?}", filter_documentos);

    // Buscar documentos que coinciden con el filtro
    let mut cursor_documentos = documentos_collection
        .find(filter_documentos, None)
        .await
        .map_err(|e| e.to_string())?;

    // Recopilar los resultados de documentos
    let mut resultados_documentos = Vec::new();
    while let Some(mut doc) = cursor_documentos
        .try_next()
        .await
        .map_err(|e| e.to_string())?
    {
        if let Some(nombre_archivo) = doc.get("filename").and_then(|f| f.as_str()) {
            if let Some(tipo_archivo) = detectar_tipo_archivo(nombre_archivo) {
                doc.insert("tipo_archivo", tipo_archivo);
            }
        }
        resultados_documentos.push(doc);
    }

    println!("Documentos encontrados: {}", resultados_documentos.len());
    Ok(resultados_documentos)
}

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
    referenciadms: String, // Cambiado a opcional
}

#[tauri::command]
async fn buscar_orden(
    codigo: Option<String>,
    dni: Option<String>,
    nombre: Option<String>,
) -> Result<Vec<Orden>, String> {
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;
    let collection: Collection<Orden> = client.database("business_db").collection("ordenes");

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

    let cursor = collection
        .find(filter, None)
        .await
        .map_err(|e| e.to_string())?;
    let ordenes: Vec<Orden> = cursor.try_collect().await.map_err(|e| e.to_string())?;

    Ok(ordenes)
}

#[tauri::command]
async fn insertar_orden(
    codigo: String,
    dni: String,
    nombre: String,
    matricula: String,
    referenciadms: String,
) -> Result<i64, String> {
    println!(
        "Datos recibidos - codigo: {}, dni: {}, nombre: {}, matricula: {}, referenciadms: {}",
        codigo, dni, nombre, matricula, referenciadms
    );
    let client = get_mongo_client().await.map_err(|e| {
        println!("Error conectando a MongoDB: {}", e);
        e.to_string()
    })?;

    let collection: Collection<Orden> = client.database("business_db").collection("ordenes");

    // Verificar si la referencia DMS ya existe
    let filter_dms = doc! {
        "referenciadms": &referenciadms,  // Buscar por referencia DMS
    };

    if let Some(existing_order) = collection
        .find_one(filter_dms, None)
        .await
        .map_err(|e| e.to_string())?
    {
        println!("La referencia DMS ya existe: {:?}", existing_order);
        return Ok(existing_order.id_orden); // Retornar el ID de la orden existente
    }

    // Obtener la última orden para generar un nuevo id autoincremental
    let last_order: Option<Orden> = collection
        .find_one(
            None,
            FindOneOptions::builder()
                .sort(doc! { "idOrden": -1 })
                .build(),
        )
        .await
        .map_err(|e| e.to_string())?;

    let new_id_orden = match last_order {
        Some(orden) => orden.id_orden + 1,
        None => 1,
    };

    // Crear una nueva orden con el nuevo campo
    let nueva_orden = Orden {
        id_orden: new_id_orden,
        codigo: codigo.clone(),
        dni,
        nombre,
        matricula,
        referenciadms: referenciadms.clone(),
    };

    println!("Insertando nueva orden: {:?}", nueva_orden);

    // Insertar la nueva orden en la colección
    let insert_result = collection
        .insert_one(nueva_orden, None)
        .await
        .map_err(|e| e.to_string())?;

    println!("Resultado de la inserción: {:?}", insert_result);

    // Retornar el nuevo idOrden
    Ok(new_id_orden)
}


#[tauri::command]
async fn buscar_documentos_por_orden(id_orden: i64) -> Result<Vec<Document>, String> {
    // Obtener el cliente de MongoDB
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;

    // Conexión a la colección de documentos
    let collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.files");

    // Crear un filtro para obtener documentos por id_orden en metadata
    let filter = doc! { "metadata.idOrden": id_orden };

    // Buscar los documentos que coinciden con el filtro
    let mut cursor = collection
        .find(filter, None)
        .await
        .map_err(|e| e.to_string())?;

    // Recopilar los resultados
    let mut resultados = Vec::new();
    while let Some(doc) = cursor.try_next().await.map_err(|e| e.to_string())? {
        // Extraer el nombre del archivo
        if let Some(nombre_archivo) = doc.get("filename").and_then(|f| f.as_str()) {
            // Detectar el tipo de archivo
            if let Some(tipo_archivo) = detectar_tipo_archivo(nombre_archivo) {
                // Agregar el tipo de archivo al documento
                let mut doc = doc.clone();
                doc.insert("tipo_archivo", tipo_archivo);
                resultados.push(doc);
            } else {
                // Si no se detecta el tipo de archivo, se puede manejar de otra manera
                resultados.push(doc);
            }
        } else {
            resultados.push(doc); // Si no tiene filename, igual lo agregamos a los resultados
        }
    }

    Ok(resultados)
}

#[tauri::command]
async fn buscar_documentos_por_criterio_orden(
    id_orden: i64,
    criterio: String,
    tipo_archivo: Option<String>,
    fecha_inicio: Option<String>,
    fecha_fin: Option<String>,
) -> Result<Vec<Document>, String> {
    // Obtener el cliente de MongoDB
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;
    let documentos_collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.files");

    // Crear condiciones de filtro
    let mut filter_conditions = vec![doc! { "metadata.idOrden": id_orden }];

    // Agregar condiciones de búsqueda si se proporciona un criterio
    if !criterio.is_empty() {
        println!("Criterio recibido: {}", criterio);
        filter_conditions.push(doc! {
            "$or": [
                { "filename": { "$regex": &criterio, "$options": "i" } },
                { "metadata.Carpeta": { "$regex": &criterio, "$options": "i" } },
                { "metadata.NombreArchivo": { "$regex": &criterio, "$options": "i" } },
                { "metadata.idDocumento": { "$regex": &criterio, "$options": "i" } },
            ]
        });
    }

    // Agregar condición de tipo de archivo si se proporciona
    if let Some(tipo) = &tipo_archivo {
        if !tipo.is_empty() {
            println!("Tipo de archivo recibido: {}", tipo);
            filter_conditions.push(doc! {
                "metadata.tipo_archivo": { "$regex": tipo, "$options": "i" }
            });
        }
    }

    // Agregar condición de rango de fechas si se proporciona al menos una fecha
    if fecha_inicio.is_some() || fecha_fin.is_some() {
        let mut date_conditions = doc! {};
        println!(
            "Rango de fechas - Inicio: {:?}, Fin: {:?}",
            fecha_inicio, fecha_fin
        );

        if let Some(fecha_ini) = &fecha_inicio {
            let fecha_inicio_dt =
                DateTime::parse_rfc3339_str(&fecha_ini).map_err(|e| e.to_string())?;
            date_conditions.insert("$gte", fecha_inicio_dt);
        }

        if let Some(fecha_fin) = &fecha_fin {
            let fecha_fin_dt =
                DateTime::parse_rfc3339_str(&fecha_fin).map_err(|e| e.to_string())?;
            date_conditions.insert("$lte", fecha_fin_dt);
        }

        filter_conditions.push(doc! {
            "metadata.FechaUltimaModificacion": date_conditions
        });
    }

    // Construir el filtro final combinando todas las condiciones
    let filter_documentos = doc! { "$and": filter_conditions };
    println!("Condiciones de filtro aplicadas: {:?}", filter_documentos);

    // Buscar documentos que coinciden con el filtro
    let mut cursor_documentos = documentos_collection
        .find(filter_documentos, None)
        .await
        .map_err(|e| e.to_string())?;

    // Recopilar los resultados de documentos
    let mut resultados_documentos = Vec::new();
    while let Some(mut doc) = cursor_documentos
        .try_next()
        .await
        .map_err(|e| e.to_string())?
    {
        if let Some(nombre_archivo) = doc.get("filename").and_then(|f| f.as_str()) {
            if let Some(tipo_archivo) = detectar_tipo_archivo(nombre_archivo) {
                doc.insert("tipo_archivo", tipo_archivo);
            }
        }
        resultados_documentos.push(doc);
    }

    println!("Documentos encontrados: {}", resultados_documentos.len());
    Ok(resultados_documentos)
}

#[derive(Debug, Serialize, Deserialize)]
struct Cliente {
    id_cliente: i64,
    codigo: String,
    dni: String,
    nombre: String,
    referenciadms: Option<String>, // Cambiado a campo opcional
}

#[tauri::command]
async fn buscar_cliente(
    codigo: Option<String>,
    dni: Option<String>,
    nombre: Option<String>,
) -> Result<Vec<Cliente>, String> {
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;
    let collection: Collection<Cliente> = client.database("business_db").collection("cliente");

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

    // Realizar la búsqueda
    let cursor = collection
        .find(filter, None)
        .await
        .map_err(|e| e.to_string())?; // Explicitly convert the error here
    let clientes: Vec<Cliente> = cursor.try_collect().await.map_err(|e| e.to_string())?;

    Ok(clientes)
}

#[tauri::command]
async fn insertar_cliente(
    codigo: String,
    dni: String,
    nombre: String,
    referenciadms: Option<String>,
) -> Result<i64, String> {
    println!("Referencia DMS recibida: {:?}", referenciadms); // Debug: Verificar el valor de referenciadms
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;
    let collection: Collection<Cliente> = client.database("business_db").collection("cliente");

    let last_client: Option<Cliente> = collection
        .find_one(
            None,
            FindOneOptions::builder()
                .sort(doc! { "id_cliente": -1 })
                .build(),
        )
        .await
        .map_err(|e| e.to_string())?;

    let new_id_cliente = match last_client {
        Some(cliente) => cliente.id_cliente + 1,
        None => 1,
    };

    let nuevo_cliente = Cliente {
        id_cliente: new_id_cliente,
        codigo,
        dni,
        nombre,
        referenciadms, // Se pasará el valor recibido
    };

    collection
        .insert_one(nuevo_cliente, None)
        .await
        .map_err(|e| e.to_string())?;

    Ok(new_id_cliente)
}

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
    fecha_ultima_modificacion: Option<i64>, // Cambiar a Option<i64>
    #[serde(rename = "idOrden")]
    id_orden: Option<i64>,
    #[serde(rename = "idVehiculo")]
    id_vehiculo: Option<i64>,
    #[serde(rename = "id_cliente")]
    id_cliente: Option<i64>,
    #[serde(rename = "tamano_archivo")]
    tamano_archivo: i64, // Asegúrate de que este campo esté aquí
                         // El campo `archivo` ha sido eliminado
}

#[tauri::command]
async fn find_all_documentos() -> Result<Vec<Documento>, String> {
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;
    let collection: Collection<Documento> = client
        .database("business_db")
        .collection("documentos.files");

    let cursor = collection
        .find(None, None)
        .await
        .map_err(|e| e.to_string())?; // Explicitly convert the error here
    let documentos: Vec<Documento> = cursor.try_collect().await.map_err(|e| e.to_string())?;

    Ok(documentos)
}

// Función auxiliar para detectar el tipo de archivo
fn detectar_tipo_archivo(nombre_archivo: &str) -> Option<String> {
    // Define un mapa de extensiones a tipos de archivo
    let extensiones: std::collections::HashMap<&str, &str> = [
        ("pdf", "Documento PDF"),
        ("doc", "Documento Word"),
        ("docx", "Documento Word"),
        ("xls", "Hoja de cálculo Excel"),
        ("xlsx", "Hoja de cálculo Excel"),
        ("jpg", "Imagen JPEG"),
        ("jpeg", "Imagen JPEG"),
        ("png", "Imagen PNG"),
        ("gif", "Imagen GIF"),
        ("txt", "Archivo de texto"),
        ("zip", "Archivo comprimido"),
        ("rar", "Archivo comprimido RAR"),
    ]
    .iter()
    .cloned()
    .collect();

    // Extraer la extensión del nombre del archivo
    let extension = Path::new(nombre_archivo)
        .extension()
        .and_then(std::ffi::OsStr::to_str);

    // Retornar el tipo de archivo según la extensión
    extension.and_then(|ext| extensiones.get(ext).map(|&tipo| tipo.to_string()))
}

#[tauri::command]
async fn buscar_documentos_por_cliente(id_cliente: i64) -> Result<Vec<Document>, String> {
    // Obtener el cliente de MongoDB
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;

    // Conexión a la colección
    let collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.files");

    // Crear un filtro para obtener documentos por id_cliente en metadata
    let filter = doc! { "metadata.id_cliente": id_cliente };

    // Buscar los documentos que coinciden con el filtro
    let mut cursor = collection
        .find(filter, None)
        .await
        .map_err(|e| e.to_string())?;

    // Recopilar los resultados
    let mut resultados = Vec::new();
    while let Some(doc) = cursor.try_next().await.map_err(|e| e.to_string())? {
        // Extraer el nombre del archivo
        if let Some(nombre_archivo) = doc.get("filename").and_then(|f| f.as_str()) {
            // Detectar el tipo de archivo
            if let Some(tipo_archivo) = detectar_tipo_archivo(nombre_archivo) {
                // Agregar el tipo de archivo al documento
                let mut doc = doc.clone();
                doc.insert("tipo_archivo", tipo_archivo);
                resultados.push(doc);
            } else {
                // Si no se detecta el tipo de archivo, se puede manejar de otra manera
                resultados.push(doc);
            }
        } else {
            resultados.push(doc); // Si no tiene filename, igual lo agregamos a los resultados
        }
    }

    Ok(resultados)
}

#[tauri::command]
async fn buscar_documentos_por_cliente_qae(referencia_dms: &str) -> Result<Vec<Document>, String> {
    // Obtener el cliente de MongoDB
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;

    // Conexión a la colección
    let collection: Collection<Document> = client.database("quiter-qae").collection("FMCUCG.files");

    println!("Referencia DMS buscada: {}", referencia_dms);

    // Crear un filtro para obtener documentos por referencia_dms en metadata
    let filter = doc! { "metadata.referenciaDms": referencia_dms };

    // Buscar los documentos que coinciden con el filtro
    let mut cursor = collection
        .find(filter, None)
        .await
        .map_err(|e| e.to_string())?;

    // Recopilar los resultados
    let mut resultados = Vec::new();
    while let Some(mut doc) = cursor.try_next().await.map_err(|e| e.to_string())? {
        // Extraer el nombre del archivo directamente como filename
        if let Some(filename) = doc.get("filename").and_then(|f| f.as_str()) {
            // Detectar el mimetype del archivo si no está presente en metadata
            if doc
                .get("metadata")
                .and_then(|m| m.as_document())
                .and_then(|m| m.get("mimetype"))
                .is_none()
            {
                if let Some(mimetype) = detectar_tipo_archivo(filename) {
                    // Agregar el mimetype al campo metadata
                    doc.entry("metadata".to_string())
                        .or_insert_with(|| doc! {}.into())
                        .as_document_mut()
                        .unwrap()
                        .insert("mimetype", Bson::String(mimetype.to_string()));
                }
            }
            // Imprimir el documento en la consola para depuración
            println!("{:?}", doc);
            resultados.push(doc);
        } else {
            println!("{:?}", doc); // Imprimir el documento si no tiene filename también
            resultados.push(doc); // Si no tiene filename, igual lo agregamos a los resultados
        }
    }

    Ok(resultados)
}

// Función para descargar el documento
#[tauri::command]
async fn descargar_documento(id_documento: i64) -> Result<(Vec<u8>, String), String> {
    // Obtener el cliente de MongoDB
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;

    // Conexión a la colección 'documentos.files'
    let files_collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.files");

    // Buscar el documento por idDocumento en metadata
    let filter = doc! { "metadata.idDocumento": id_documento };
    let document = files_collection
        .find_one(filter, None)
        .await
        .map_err(|e| e.to_string())?;

    // Verificar si se encontró el documento
    let doc_to_download = match document {
        Some(doc) => doc,
        None => {
            return Err(format!(
                "No se encontró ningún documento con idDocumento: {}",
                id_documento
            ))
        }
    };

    // Obtener el ObjectId del archivo
    let file_id = doc_to_download
        .get_object_id("_id")
        .map_err(|e| e.to_string())?;
    let nombre_archivo = doc_to_download
        .get_str("filename")
        .map_err(|e| e.to_string())?
        .to_string();

    // Conexión a la colección 'documentos.chunks'
    let chunks_collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.chunks");

    // Buscar todos los chunks relacionados con el file_id
    let chunks_filter = doc! { "files_id": file_id };
    let mut chunks_cursor = chunks_collection
        .find(chunks_filter, None)
        .await
        .map_err(|e| e.to_string())?;

    // Buffer para almacenar los datos del archivo
    let mut buffer = Vec::new();

    // Leer todos los chunks y combinarlos en el buffer
    while let Some(chunk) = chunks_cursor.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        let chunk_data = chunk
            .get_binary_generic("data")
            .map_err(|e| e.to_string())?;
        buffer.extend_from_slice(chunk_data);
    }

    Ok((buffer, nombre_archivo))
}

#[tauri::command]
async fn eliminar_documento(id_documento: i64) -> Result<(), String> {
    // Obtener el cliente de MongoDB
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;

    // Conexión a las colecciones
    let files_collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.files");
    let chunks_collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.chunks");

    // Filtro para encontrar el documento por idDocumento
    let filter = doc! { "metadata.idDocumento": id_documento };

    // Buscar el documento para obtener el ObjectId
    let document = files_collection
        .find_one(filter.clone(), None)
        .await
        .map_err(|e| e.to_string())?;

    // Verificar si se encontró el documento
    let doc_to_delete = match document {
        Some(doc) => doc,
        None => {
            return Err(format!(
                "No se encontró ningún documento con idDocumento: {}",
                id_documento
            ))
        }
    };

    // Obtener el _id del documento
    let file_id = doc_to_delete
        .get_object_id("_id")
        .map_err(|e| e.to_string())?;

    // Intentar eliminar el documento de la colección principal
    let delete_result = files_collection
        .delete_one(doc! { "_id": file_id }, None)
        .await
        .map_err(|e| e.to_string())?;

    // Verificar si se eliminó algún documento
    if delete_result.deleted_count == 0 {
        return Err(format!(
            "No se pudo eliminar el documento con idDocumento: {}",
            id_documento
        ));
    }

    // Filtro para eliminar los chunks asociados usando el _id del documento eliminado
    let chunks_filter = doc! { "files_id": file_id };

    // Intentar eliminar los chunks relacionados
    let chunks_delete_result = chunks_collection
        .delete_many(chunks_filter, None)
        .await
        .map_err(|e| e.to_string())?;

    // Mensaje de confirmación sobre la eliminación de chunks
    if chunks_delete_result.deleted_count > 0 {
        println!(
            "Se eliminaron {} chunks relacionados con idDocumento: {}",
            chunks_delete_result.deleted_count, id_documento
        );
    }

    Ok(())
}

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
    id_orden: Option<i64>,
    id_vehiculo: Option<i64>,
    id_cliente: Option<i64>,
    file: Vec<u8>,
    tamano_archivo: i64,
) -> Result<(), String> {
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;

    // Acceder a la colección 'documentos.files'
    let files_collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.files");

    // Obtener el máximo idDocumento de la colección
    let last_document: Option<Document> = files_collection
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

    // Calcular el nuevo idDocumento
    let nuevo_id_documento = match last_document {
        Some(doc) => {
            let metadata = doc.get_document("metadata").map_err(|e| e.to_string())?; // Obtener metadata
            metadata
                .get_i64("idDocumento") // Esto devuelve un Result
                .map(|id| id + 1) // Incrementar si es Ok
                .unwrap_or(1) // Si hay un error, iniciar en 1
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

    // Generar la descripción: 'Fichero ' + nombre_archivo
    let descripcion = format!("Fichero {}", nombre_archivo);

    // Preparar los metadatos
    let metadata = doc! {
        "idDocumento": nuevo_id_documento,
        "idUsuario": id_usuario,
        "Carpeta": carpeta,
        "NombreArchivo": nombre_archivo.clone(),
        "tipo_archivo": tipo_archivo,
        "Mimetype": mimetype,
        "FicheroDMS": fichero_dms,
        "ReferenciaDMS": referencia_dms,
        "UsuarioDMS": usuario_dms,
        "FechaUltimaModificacion": fecha_modificacion,
        "idOrden": id_orden,
        "idVehiculo": id_vehiculo,
        "id_cliente": id_cliente,
        "tamano_archivo": tamano_archivo,
        "descripcion": descripcion, // Aquí incluimos la descripción
    };

    // Usar open_upload_stream con metadatos
    let upload_options = GridFsUploadOptions::builder().metadata(metadata).build();

    let mut upload_stream = bucket.open_upload_stream(nombre_archivo.clone(), upload_options);

    upload_stream
        .write_all(&file)
        .await
        .map_err(|e| e.to_string())?;
    upload_stream.close().await.map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
async fn buscar_documentos_por_busqueda(
    id_cliente: i64,
    criterio: String,
    tipo_archivo: Option<String>,
    fecha_inicio: Option<String>,
    fecha_fin: Option<String>,
) -> Result<Vec<Document>, String> {
    // Obtener el cliente de MongoDB
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;

    // Conexión a la colección de documentos
    let documentos_collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.files");

    // Crear condiciones de filtro
    let mut filter_conditions = vec![doc! { "metadata.id_cliente": id_cliente }];

    // Agregar condiciones de búsqueda si se proporciona un criterio
    if !criterio.is_empty() {
        filter_conditions.push(doc! {
            "$or": [
                { "filename": { "$regex": &criterio, "$options": "i" } },
                { "metadata.Carpeta": { "$regex": &criterio, "$options": "i" } },
                { "metadata.NombreArchivo": { "$regex": &criterio, "$options": "i" } },
                { "metadata.idDocumento": { "$regex": &criterio, "$options": "i" } },
            ]
        });
    }

    // Agregar condición de tipo de archivo si se proporciona
    if let Some(tipo) = &tipo_archivo {
        if !tipo.is_empty() {
            filter_conditions.push(doc! {
                "metadata.tipo_archivo": { "$regex": tipo, "$options": "i" }
            });
        }
    }

    // Agregar condición de rango de fechas si se proporciona al menos una fecha
    if fecha_inicio.is_some() || fecha_fin.is_some() {
        let mut date_conditions = doc! {};

        if let Some(fecha_ini) = &fecha_inicio {
            let fecha_inicio_dt =
                DateTime::parse_rfc3339_str(&fecha_ini).map_err(|e| e.to_string())?;
            date_conditions.insert("$gte", fecha_inicio_dt);
        }

        if let Some(fecha_fin) = &fecha_fin {
            let fecha_fin_dt =
                DateTime::parse_rfc3339_str(&fecha_fin).map_err(|e| e.to_string())?;
            date_conditions.insert("$lte", fecha_fin_dt);
        }

        filter_conditions.push(doc! {
            "metadata.FechaUltimaModificacion": date_conditions
        });
    }

    // Construir el filtro final combinando todas las condiciones
    let filter_documentos = doc! {
        "$and": filter_conditions
    };

    // Buscar documentos que coinciden con el filtro
    let mut cursor_documentos = documentos_collection
        .find(filter_documentos, None)
        .await
        .map_err(|e| e.to_string())?;

    // Recopilar los resultados de documentos
    let mut resultados_documentos = Vec::new();
    while let Some(mut doc) = cursor_documentos
        .try_next()
        .await
        .map_err(|e| e.to_string())?
    {
        // Extraer el nombre del archivo
        if let Some(nombre_archivo) = doc.get("filename").and_then(|f| f.as_str()) {
            // Detectar el tipo de archivo
            if let Some(tipo_archivo) = detectar_tipo_archivo(nombre_archivo) {
                // Agregar el tipo de archivo al documento
                doc.insert("tipo_archivo", tipo_archivo);
            }
        }
        resultados_documentos.push(doc);
    }

    Ok(resultados_documentos)
}

#[tauri::command]
async fn buscar_cliente_por_documento(id_documento: i64) -> Result<Option<Cliente>, String> {
    // Obtener el cliente de MongoDB
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;

    // Conexión a la colección de documentos
    let documentos_collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.files");

    // Buscar el documento por id_documento en metadata
    let filter = doc! { "metadata.idDocumento": id_documento };
    let documento = documentos_collection
        .find_one(filter, None)
        .await
        .map_err(|e| e.to_string())?;

    // Verificar si se encontró el documento
    let documento = match documento {
        Some(doc) => doc,
        None => return Ok(None), // Si no se encuentra el documento, retornar None
    };

    // Intentar obtener el id_cliente del documento
    let id_cliente = match documento.get_document("metadata") {
        Ok(metadata) => metadata.get_i64("id_cliente").map_err(|e| e.to_string()),
        Err(_) => Err("El campo 'metadata' no está presente".to_string()),
    }?;

    // Conexión a la colección de clientes
    let clientes_collection: Collection<Cliente> =
        client.database("business_db").collection("cliente");

    // Buscar el cliente por id_cliente
    let filter_cliente = doc! { "id_cliente": id_cliente };
    let cliente = clientes_collection
        .find_one(filter_cliente, None)
        .await
        .map_err(|e| e.to_string())?;

    // Retornar el cliente encontrado (o None si no se encuentra)
    Ok(cliente)
}

#[tauri::command]
async fn obtener_imagen(id_documento: i64) -> Result<Vec<u8>, String> {
    // Obtener el cliente de MongoDB
    let client = get_mongo_client().await.map_err(|e| e.to_string())?;

    // Conexión a la colección de documentos
    let collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.files");

    // Buscar el documento por id_documento
    let filter = doc! { "metadata.idDocumento": id_documento };
    let documento = collection
        .find_one(filter, None)
        .await
        .map_err(|e| e.to_string())?;

    // Verificar si se encontró el documento
    let doc_to_download = match documento {
        Some(doc) => doc,
        None => {
            return Err(format!(
                "No se encontró ningún documento con idDocumento: {}",
                id_documento
            ))
        }
    };

    // Obtener el ObjectId del archivo
    let file_id = doc_to_download
        .get_object_id("_id")
        .map_err(|e| e.to_string())?;

    // Obtener el nombre del archivo para detectar el tipo
    let nombre_archivo = doc_to_download
        .get_str("filename")
        .map_err(|e| e.to_string())?;

    // Comprobar si el archivo es una imagen
    let es_imagen = nombre_archivo.ends_with(".jpg")
        || nombre_archivo.ends_with(".jpeg")
        || nombre_archivo.ends_with(".png")
        || nombre_archivo.ends_with(".gif");

    if !es_imagen {
        return Err(format!("Vista previa no disponible"));
    }

    // Conexión a la colección 'documentos.chunks'
    let chunks_collection: Collection<Document> = client
        .database("business_db")
        .collection("documentos.chunks");

    // Buscar todos los chunks relacionados con el file_id
    let chunks_filter = doc! { "files_id": file_id };
    let mut chunks_cursor = chunks_collection
        .find(chunks_filter, None)
        .await
        .map_err(|e| e.to_string())?;

    // Buffer para almacenar los datos del archivo
    let mut buffer = Vec::new();

    // Leer todos los chunks y combinarlos en el buffer
    while let Some(chunk) = chunks_cursor.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        let chunk_data = chunk
            .get_binary_generic("data")
            .map_err(|e| e.to_string())?;
        buffer.extend_from_slice(chunk_data);
    }

    Ok(buffer)
}

// Define la contraseña como una constante global
const DB_PASSWORD: &str = "1234";
const ENCRYPT_PASSWORD: &str = "#SynergyaTechÑ2024*";

#[derive(Serialize, Deserialize)]
struct DatosGlobales {
    idusuario_global: i32,
    nombre_global: String,
    alias_global: String,
    icono_global: String,
    nombre_grupo_global: String,
    es_administrador_global: bool,
    idempresa_global: i32,
    nombre_empresa_global: String,
    logo_empresa_global: String,
    icono_empresa_dark_global: String,
    icono_empresa_light_global: String,
    server: String,
    username: String,
    password: String,
    mongodb_server: String,
    mongodb_port: String,
    mongodb_user: String,
    mongodb_password: String,
    qae_server: String,
    qae_port: String,
    qae_user: String,
    qae_password: String,
    use_qae: bool,
    usuario_dms_qba_mongodb: String,
}

// Definición de la variable estática
static mut DATOS_GLOBALES: DatosGlobales = DatosGlobales {
    idusuario_global: 0,
    nombre_global: String::new(),
    alias_global: String::new(),
    icono_global: String::new(),
    nombre_grupo_global: String::new(),
    es_administrador_global: false,
    idempresa_global: 0,
    nombre_empresa_global: String::new(),
    logo_empresa_global: String::new(),
    icono_empresa_dark_global: String::new(),
    icono_empresa_light_global: String::new(),
    server: String::new(),
    username: String::new(),
    password: String::new(),
    mongodb_server: String::new(),
    mongodb_port: String::new(),
    mongodb_user: String::new(),
    mongodb_password: String::new(),
    qae_server: String::new(),
    qae_port: String::new(),
    qae_user: String::new(),
    qae_password: String::new(),
    use_qae: true,
    usuario_dms_qba_mongodb: String::new(),
};

// Implementa una función para obtener los datos globales
#[tauri::command]
fn obtener_datos_globales() -> DatosGlobales {
    unsafe {
        DatosGlobales {
            idusuario_global: DATOS_GLOBALES.idusuario_global,
            nombre_global: DATOS_GLOBALES.nombre_global.clone(),
            alias_global: DATOS_GLOBALES.alias_global.clone(),
            icono_global: DATOS_GLOBALES.icono_global.clone(),
            nombre_grupo_global: DATOS_GLOBALES.nombre_grupo_global.clone(),
            es_administrador_global: DATOS_GLOBALES.es_administrador_global,
            idempresa_global: DATOS_GLOBALES.idempresa_global,
            nombre_empresa_global: DATOS_GLOBALES.nombre_empresa_global.clone(),
            logo_empresa_global: DATOS_GLOBALES.logo_empresa_global.clone(),
            icono_empresa_dark_global: DATOS_GLOBALES.icono_empresa_dark_global.clone(),
            icono_empresa_light_global: DATOS_GLOBALES.icono_empresa_light_global.clone(),
            server: DATOS_GLOBALES.server.clone(),
            username: DATOS_GLOBALES.username.clone(),
            password: DATOS_GLOBALES.password.clone(),
            mongodb_server: DATOS_GLOBALES.mongodb_server.clone(),
            mongodb_port: DATOS_GLOBALES.mongodb_port.clone(),
            mongodb_user: DATOS_GLOBALES.mongodb_user.clone(),
            mongodb_password: DATOS_GLOBALES.mongodb_password.clone(),
            qae_server: DATOS_GLOBALES.qae_server.clone(),
            qae_port: DATOS_GLOBALES.qae_port.clone(),
            qae_user: DATOS_GLOBALES.qae_user.clone(),
            qae_password: DATOS_GLOBALES.qae_password.clone(),
            use_qae: DATOS_GLOBALES.use_qae,
            usuario_dms_qba_mongodb: DATOS_GLOBALES.usuario_dms_qba_mongodb.clone(),
        }
    }
}

// Implementa una función para asignar los datos globales
#[tauri::command]
fn asignar_datos_globales(
    id_usuario: i32,
    nombre: String,
    alias: String,
    icono: String,
    nombre_grupo: String,
    es_administrador: bool,
    id_empresa: i32,
    nombre_empresa: String,
    logo_empresa: String,
    icono_empresa_dark: String,
    icono_empresa_light: String,
    server: String,
    username: String,
    password: String,
    mongodb_server: String,
    mongodb_port: String,
    mongodb_user: String,
    mongodb_password: String,
    qae_server: String,
    qae_port: String,
    qae_user: String,
    qae_password: String,
    use_qae: bool,
    usuario_dms_qba_mongodb: String,
) {
    unsafe {
        DATOS_GLOBALES.idusuario_global = id_usuario;
        DATOS_GLOBALES.nombre_global = nombre;
        DATOS_GLOBALES.alias_global = alias;
        DATOS_GLOBALES.icono_global = icono;
        DATOS_GLOBALES.nombre_grupo_global = nombre_grupo;
        DATOS_GLOBALES.es_administrador_global = es_administrador;
        DATOS_GLOBALES.idempresa_global = id_empresa;
        DATOS_GLOBALES.nombre_empresa_global = nombre_empresa;
        DATOS_GLOBALES.logo_empresa_global = logo_empresa;
        DATOS_GLOBALES.icono_empresa_dark_global = icono_empresa_dark;
        DATOS_GLOBALES.icono_empresa_light_global = icono_empresa_light;
        DATOS_GLOBALES.server = server;
        DATOS_GLOBALES.username = username;
        DATOS_GLOBALES.password = password;
        DATOS_GLOBALES.mongodb_server = mongodb_server;
        DATOS_GLOBALES.mongodb_port = mongodb_port;
        DATOS_GLOBALES.mongodb_user = mongodb_user;
        DATOS_GLOBALES.mongodb_password = mongodb_password;
        DATOS_GLOBALES.qae_server = qae_server;
        DATOS_GLOBALES.qae_port = qae_port;
        DATOS_GLOBALES.qae_user = qae_user;
        DATOS_GLOBALES.qae_password = qae_password;
        DATOS_GLOBALES.use_qae = use_qae;
        DATOS_GLOBALES.usuario_dms_qba_mongodb = usuario_dms_qba_mongodb;
    }
}

#[tauri::command]
fn actualizar_datos_globales_empresa(
    nombre_empresa: String,
    logo_empresa: Option<String>,
    icono_empresa_dark: Option<String>,
    icono_empresa_light: Option<String>,
) {
    unsafe {
        DATOS_GLOBALES.nombre_empresa_global = nombre_empresa;
        DATOS_GLOBALES.logo_empresa_global = logo_empresa.unwrap_or_else(|| String::new());
        DATOS_GLOBALES.icono_empresa_dark_global =
            icono_empresa_dark.unwrap_or_else(|| String::new());
        DATOS_GLOBALES.icono_empresa_light_global =
            icono_empresa_light.unwrap_or_else(|| String::new());
    }
}

#[tauri::command]
fn actualizar_datos_globales_servidor(
    server: Option<String>,
    username: Option<String>,
    password: Option<String>,
    mongodb_server: Option<String>,
    mongodb_port: Option<String>,
    mongodb_user: Option<String>,
    mongodb_password: Option<String>,
    qae_server: Option<String>,
    qae_port: Option<String>,
    qae_user: Option<String>,
    qae_password: Option<String>,
    use_qae: Option<bool>,
    usuario_dms_qba_mongodb: Option<String>,
) {
    unsafe {
        if let Some(server) = server {
            DATOS_GLOBALES.server = server;
        }
        if let Some(username) = username {
            DATOS_GLOBALES.username = username;
        }
        if let Some(password) = password {
            DATOS_GLOBALES.password = password;
        }
        if let Some(mongodb_server) = mongodb_server {
            DATOS_GLOBALES.mongodb_server = mongodb_server;
        }
        if let Some(mongodb_port) = mongodb_port {
            DATOS_GLOBALES.mongodb_port = mongodb_port;
        }
        if let Some(mongodb_user) = mongodb_user {
            DATOS_GLOBALES.mongodb_user = mongodb_user;
        }
        if let Some(mongodb_password) = mongodb_password {
            DATOS_GLOBALES.mongodb_password = mongodb_password;
        }
        if let Some(qae_server) = qae_server {
            DATOS_GLOBALES.qae_server = qae_server;
        }
        if let Some(qae_port) = qae_port {
            DATOS_GLOBALES.qae_port = qae_port;
        }
        if let Some(qae_user) = qae_user {
            DATOS_GLOBALES.qae_user = qae_user;
        }
        if let Some(qae_password) = qae_password {
            DATOS_GLOBALES.qae_password = qae_password;
        }
        if let Some(use_qae) = use_qae {
            DATOS_GLOBALES.use_qae = use_qae;
        }
        if let Some(usuario_dms_qba_mongodb) = usuario_dms_qba_mongodb {
            DATOS_GLOBALES.usuario_dms_qba_mongodb = usuario_dms_qba_mongodb;
        }
    }
}

// Implementa una función para obtener la contraseña
#[tauri::command]
fn obtener_contrasena() -> String {
    DB_PASSWORD.to_string()
}

#[tauri::command]
fn obtener_contrasena_encrypt() -> String {
    ENCRYPT_PASSWORD.to_string()
}

// Implementa una función para salir de la aplicación
#[tauri::command]
fn exit_app() {
    std::process::exit(0x0);
}

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
        .expect("Unable to create uopy.ini");
    file.write_all(ini_content.as_bytes())
        .await
        .expect("Unable to write to uopy.ini");
}

async fn delete_uopy_ini() {
    // Adding a short delay to ensure the backend initialization has completed
    sleep(Duration::from_secs(3)).await;
    fs::remove_file("uopy.ini")
        .await
        .expect("Unable to delete uopy.ini");
}

struct PythonBackend {
    stdin: std::process::ChildStdin,
    stdout: Arc<Mutex<BufReader<std::process::ChildStdout>>>,
}

impl PythonBackend {
    fn new(_app_handle: &tauri::AppHandle) -> Self {
        //let system32_path = env::var("SystemRoot")
        //    .map(|system_root| PathBuf::from(system_root).join("System32"))
        //    .unwrap_or_else(|_| PathBuf::from("C:\\Windows\\System32"));

        let app_path = env::current_exe()
            .ok()
            .and_then(|exe_path| exe_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));

        // Obtener la ruta de System32 o usar la ruta de la aplicación si no se encuentra
        let system32_path = env::var("SystemRoot")
            .map(|system_root| PathBuf::from(system_root).join("System32"))
            .unwrap_or_else(|_| app_path.clone());

        // Verificar si el archivo existe en alguna de las rutas
        let backend_path = [system32_path, app_path]
            .iter()
            .map(|path| path.join("brcom.dll"))
            .find(|path| path.exists())
            .expect("brcom.dll no encontrado en ninguna de las rutas.");

        // Imprimir las rutas para verificación
        println!("Backend path: {:?}", backend_path);

        let mut child = Command::new(&backend_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to spawn process: {:?}\nAttempted path: {:?}",
                    e, backend_path
                )
            });

        let stdin = child.stdin.take().expect("Failed to open stdin");
        let stdout = BufReader::new(child.stdout.take().expect("Failed to open stdout"));

        PythonBackend {
            stdin,
            stdout: Arc::new(Mutex::new(stdout)),
        }
    }

    fn send_command(&mut self, input: &str) -> String {
        writeln!(self.stdin, "{}", input).expect("Failed to write to stdin");

        let mut response = String::new();
        self.stdout
            .lock()
            .unwrap()
            .read_line(&mut response)
            .expect("Failed to read from stdout");
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

    let unescaped_response = match serde_json::from_str::<Value>(&response) {
        Ok(Value::String(s)) => s,
        _ => response,
    };

    match serde_json::from_str::<serde_json::Value>(&unescaped_response) {
        Ok(_) => Ok(unescaped_response),
        Err(_) => {
            Ok(serde_json::json!({"error": "Invalid response from Python backend"}).to_string())
        }
    }
}

#[tokio::main]
async fn main() {
    create_uopy_ini().await;

    tauri::Builder::default()
        .setup(|app| {
            let python_backend = Arc::new(Mutex::new(PythonBackend::new(&app.handle())));
            app.manage(python_backend);

            let handle = app.handle();
            tokio::spawn(async move {
                delete_uopy_ini().await;
            });

            #[cfg(debug_assertions)]
            {
                let window = handle.get_window("main").unwrap();
                //window.open_devtools();
            }

            Ok(())
        })
        .plugin(tauri_plugin_sqlite::init())
        .invoke_handler(tauri::generate_handler![
            obtener_datos_globales,
            asignar_datos_globales,
            actualizar_datos_globales_empresa,
            exit_app,
            obtener_contrasena,
            api_command_py,
            encrypt,
            decrypt,
            find_all_documentos, // Añadido aquí
            buscar_cliente,      // Añadido aquí
            insertar_cliente,
            buscar_documentos_por_cliente,
            eliminar_documento,
            insertar_documento, // Añadido aquí
            descargar_documento,
            buscar_documentos_por_busqueda,
            verificar_conexion_mongodb,
            buscar_cliente_por_documento,
            obtener_imagen,
            actualizar_datos_globales_servidor,
            obtener_contrasena_encrypt,
            insertar_orden,
            buscar_orden,
            buscar_documentos_por_orden,
            buscar_documentos_por_criterio_orden,
            insertar_vehiculo,
            buscar_vehiculo,
            buscar_documentos_por_vehiculo,
            buscar_documentos_por_criterio_vehiculo,
            buscar_documentos_por_cliente_qae
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
