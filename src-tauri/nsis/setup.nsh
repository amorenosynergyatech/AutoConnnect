!macro customInstall
  ; Crear carpeta destino real
  CreateDirectory "$INSTDIR\config"

  ; Copiar desde donde Tauri coloca los recursos
  SetOutPath "$INSTDIR\config"
  File /r "${PROJECTROOT}\src-tauri\config\*.*"
!macroend
