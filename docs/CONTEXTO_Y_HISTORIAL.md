# Contexto Completo, Historial de Decisiones y Especificaciones

## 1. Origen y Objetivo del Proyecto
Herramienta portátil (ejecutable desde USB o carpeta local) para técnicos de soporte TI en sedes de **Universidad Norbert Wiener** e **Instituto Carrión**.
El flujo operativo consta de dos fases integradas en una interfaz gráfica de dos pestañas:
1. **Pestaña 1 (Recolección en sitio):** Escanea el equipo actual, clasifica su ubicación, permite editar campos con alertas visuales, guarda `<HOSTNAME>.<DOMINIO>.txt` en subcarpetas por categoría/área y audita cambios frente a escaneos previos.
2. **Pestaña 2 (Consolidación y Nube):** Lee todos los `.txt` de las subcarpetas, permite editar celdas en un `DataGridView`, exporta un `.xlsx` nativo multi-pestaña (`ADMINISTRATIVOS`, `AULAS`, `LABORATORIO`, `TODOS`) y copia filas sin encabezados al portapapeles (`TSV`) para pegar directamente con `Ctrl + V` en el inventario maestro en la nube.

## 2. Problemas Resueltos Durante el Desarrollo (Lecciones Aprendidas)
- **Eliminación de `wmic`:** Reemplazado por clases CIM/WMI (`Win32_ComputerSystem`, `Win32_BIOS`, `Win32_BaseBoard`, `Win32_SystemEnclosure`, `Win32_PhysicalMemory`, `MSFT_PhysicalDisk`, `WmiMonitorID`).
- **Valores inválidos / relleno de fábrica:** Equipos ensamblados devuelven `Default string` o `To be filled by O.E.M.`, y algunos monitores secundarios devuelven `"1"` o `"00000000"` en su serie EDID. La función `CleanValue(..., isSerial: true)` descarta cadenas menores a 4 caracteres o de dígitos repetidos y marca `(validar presencialmente)` resaltando la celda en amarillo.
- **Respaldo de Serie en Placa Base:** Si `Win32_BIOS.SerialNumber` no es válido, se consulta `Win32_BaseBoard.SerialNumber` antes de pedir validación presencial.
- **Exclusión de unidades USB:** `MSFT_PhysicalDisk` filtra `BusType != 7` (USB) para no listar la memoria USB del técnico como disco duro del equipo.
- **Perfiles de Usuario y Active Directory:** Se lee `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` filtrando SIDs `S-1-5-21-*` y `S-1-12-1-*`, traduciendo el SID a `DOMINIO\usuario` y consultando Active Directory vía `DirectorySearcher` (`displayName`, `mail`, `userPrincipalName`).
- **Bloqueo de `.exe` por Smart App Control:** Al compilar un `.exe` con `csc.exe` sin firma digital, Windows 11 bloqueó su ejecución (`InvalidOperationException: Una directiva de Control de aplicaciones bloqueó este archivo`). Se resolvió ejecutando C# nativo en memoria desde `.bat` y ocultando la consola con `ShowWindow(GetConsoleWindow(), 0)`.
- **Regreso al `.exe` (2026-11-18):** Se decidió distribuir `InventarioTI.exe` como vía principal, manteniendo `Iniciar_Inventario.bat` como respaldo. Hallazgos: el bloqueo anterior ocurrió en la PC personal del técnico (Smart App Control), no en equipos de la sede, que usan **Kaspersky**. Ejecutar como administrador **no** evita estos bloqueos (dependen de firma/reputación, no de privilegios). Estrategia: compilar con `Compilar_Exe.bat` (manifiesto `asInvoker`, metadatos de versión), enviar el SHA-256 a Seguridad TI para la lista blanca de Kaspersky y evaluar un certificado de firma de código (pendiente consultar si la institución tiene uno) para no tener que re-aprobar cada versión.
- **Sin elevación (2026-11-18):** Se probó sin privilegios de administrador cada consulta del programa (`Win32_ComputerSystem`, `Win32_SystemEnclosure`, `Win32_ComputerSystemProduct`, `Win32_BIOS`, `Win32_BaseBoard`, `Win32_OperatingSystem`, `Win32_Processor`, `Win32_PhysicalMemory`, `MSFT_PhysicalDisk`, `Win32_DiskDrive`, `WmiMonitorID`, `Win32_UserAccount`, Registro `ProfileList`/`CurrentVersion`, traducción de SID, `NetworkInterface`): todas responden igual. Por eso el manifiesto pasó de `requireAdministrator` a `asInvoker`. La consulta a Active Directory usa la identidad del usuario de dominio, no la elevación.
- **Error `UnauthorizedAccessException` en raíz de unidad (`D:\`):** `Directory.GetFiles` con `SearchOption.AllDirectories` fallaba al intentar leer `D:\System Volume Information`. Se reemplazó por `GetInventoryTxtFiles()`, que solo revisa el directorio raíz (`TopDirectoryOnly`) y las subcarpetas `ADMINISTRATIVOS`, `AULAS` y `LABORATORIO`.
- **Primer release v1.0.0 (2026-11-18):** La numeración de versiones reinicia en 1.0.0 (antes el título decía v3.1). Para la USB/SSD se distribuye un único ZIP con `InventarioTI.exe` y un `Iniciar_Inventario.bat` autónomo con el código C# embebido, generado por `Empaquetar_Release.bat`. No se fusionan `.exe` y `.bat` en un solo archivo: son formatos distintos y los archivos híbridos son marcados como sospechosos por los antivirus. El repositorio `aarneth/inventario-ti` es privado y el responsable copia el ZIP a los técnicos.
- **Gestión de cambios (2026-11-18):** Al validar la comparación de `.txt` existente se encontraron cuatro fallas, todas corregidas:
  - "Guardar historial" estaba invertido: archivaba el reporte NUEVO y dejaba el viejo como vigente, así que el cambio nunca llegaba al Excel.
  - La IP y el DNS generaban falsas alarmas.
  - No se detectaba el reporte anterior si el equipo cambiaba de área.
  - Las ediciones de la pestaña 2 se perdían al recargar.
  Se agregaron: edición manual en ambas pestañas (persistida como `Ajuste Manual` en el `.txt`), un comparador campo por campo con elección por fila y la comparación automática con el Excel exportado anterior al exportar. También se corrigió un error de layout por el que los botones GUARDAR y EXPORTAR quedaban fuera de la ventana.
- **Detección real de Antivirus, Absolute y HP Insights (2026-11-18):** antes las tres columnas eran fijas (`SÍ`, y HP INSIGHTS por marca). Ahora el escaneo las detecta sin permisos de administrador y las guarda en el `.txt` (líneas `Antivirus`, `Absolute`, `HP Insights`, comparadas campo por campo al guardar):
  - **Antivirus:** productos de `root\SecurityCenter2\AntiVirusProduct` con su estado (activo/inactivo); si no hay Centro de Seguridad (Windows Server), servicios de Kaspersky (sin contar el Agente de red). Columna `SÍ` solo si es Kaspersky (decisión del usuario).
  - **Absolute:** servicios `rpcnet`, `rpcnetp`, `CTES*`, `Absolute*` o con "Absolute"/"Computrace" en el nombre, programas de Absolute Software, archivos `rpcnet(p).exe` en System32/SysWOW64 y la clave `HKLM\SOFTWARE\Absolute Software`.
  - **HP Insights:** servicios y programas "HP Insights", "HP Touchpoint Analytics", "HP TechPulse" o "HP ... Workforce Experience" (no confundir con el servicio de Microsoft "Insights de calidad y uso").
  - Se quitó la `OBSERVACIÓN` "LENOVO SIN INSIGHT". Reportes de versiones anteriores y filas manuales muestran `NO VERIFICADO` hasta volver a escanear el equipo.
  - No se pudo probar en un equipo con Kaspersky, Absolute o HP Insights instalados: si en un equipo real no se detecta, revisar el nombre del servicio/programa y agregarlo a los patrones de `DetectAbsolute` / `DetectHpInsightsAgent`.
- **Acerca de (2026-11-18):** menú `Ayuda > Acerca de...` (F1) con autor (Aaron Keneth Gonzales Cortez), año de creación 2026, agradecimiento y herramientas utilizadas.

## 3. Estructura Exacta de Columnas del Excel Maestro
1. `TIPO` (`PC` o `LAPTOP`)
2. `PISO` (`1`, `2`, `3`, `4`, `SÓTANO ANEXO`, etc.)
3. `ESTADO` (`OPERATIVO`)
4. `MARCA` (`HP`, `LENOVO`, `DELL`, etc.)
5. `MODELO` (limpio sin prefijo de marca redundante, ej. `ProBook 450 G10`, `Pro Mini 400 G9`, `ThinkCentre M70q Tiny`)
6. `SERIE`
7. `PROCESADOR`
8. `RAM` (ej. `32 GB`, `8 GB`)
9. `DISCO DURO` (normalizado comercialmente: `500 GB`, `512 GB`, `1 TB`, `256 GB`)
10. `MAC ADDRESS` (formato con dos puntos en mayúsculas: `24:FB:E3:C1:37:EE`)
11. `HOST NAME`
12. `MONITOR-MODELO` (vacío en `LAPTOP`)
13. `SERIE MONITOR` (vacío en `LAPTOP`)
14. `AREA` (ej. `SAE`, `VENTAS`, `SOPORTE TÉCNICO`, `AULA 101`, `LABORATORIO DE COMPUTO 100`)
15. `REMACHADO / CADENA DE SEGURIDAD`
16. `AULA / LAB / ADMINISTRATIVO` (`ADMINISTRATIVO` para administrativos, o el nombre del aula/laboratorio)
17. `FECHA DE INVENTARIO` (`yyyy-MM-dd`)
18. `ORGANIZACIÓN` (`IDAC` para Carrión, `UPNW` u otra sigla configurable para Wiener)
19. `ANTIVIRUS` (`SÍ` solo si se detecta Kaspersky; `NO` si no; `NO VERIFICADO` en reportes sin detección y filas manuales)
20. `NOMBRE Y APELLIDO DE USUARIO` (`NOMBRE 1/NOMBRE 2` o `DOCENTE`)
21. `CORREO DE USUARIO` (`correo1@dominio/correo2@dominio`)
22. `ABSOLUTE` (`SÍ` si se detecta el agente Absolute/Computrace; `NO` si no; `NO VERIFICADO` sin detección)
23. `HP INSIGHTS` (en equipos HP: `SÍ`/`NO` según el agente HP Insights detectado, o `NO VERIFICADO`; otras marcas: siempre `NO`)
24. `CONTRATO` (vacío para edición manual)
25. `AÑO F.` (vacío para edición manual)
26. `TECNICO RESPONSABLE` (`PRIMER_NOMBRE PRIMER_APELLIDO/PRIMER_NOMBRE PRIMER_APELLIDO`)
27. `OBSERVACIÓN` *(Solo en pestaña ADMINISTRATIVOS y TODOS)*

## 4. Mejoras Futuras / Backlog Propuesto
- Importación del archivo Excel maestro descargado de la nube (`CARRION SJL.xlsx` o equivalente de Wiener) para cruzar datos y resaltar equipos nuevos vs. modificados.
- Soporte para registrar múltiples monitores en puestos administrativos con doble pantalla.
- Escaneo remoto en red LAN/Dominio por rango de IPs o lista de hostnames.