# Business Connect

Aplicación conectora entre una app móvil y un backend, desarrollada con Tauri.

## Características

- Servidor HTTP embebido para recibir solicitudes de la app móvil
- Comunicación con un backend a través de un archivo DLL
- Menú en la bandeja de tareas de Windows
- Ejecución automática al inicio de Windows
- Encriptación y desencriptación de datos

## Requisitos

- Windows 10 o superior
- Node.js y npm
- Rust y Cargo

## Instalación

1. Clonar el repositorio
2. Instalar dependencias: `npm install`
3. Compilar la aplicación: `npm run tauri build`

## Uso

La aplicación se ejecuta automáticamente al inicio de Windows y se muestra en la bandeja de tareas.

### Opciones del menú

- **Configuración**: Abre la ventana de configuración
- **Salir**: Cierra la aplicación

### API

La aplicación expone los siguientes endpoints:

- `POST /api`: Recibe solicitudes de la app móvil
- `GET /status`: Verifica el estado del conector

## Desarrollo

1. Iniciar el servidor de desarrollo: `npm run tauri dev`
2. Compilar para producción: `npm run tauri build`

## Licencia

Este proyecto está licenciado bajo la Licencia MIT.
