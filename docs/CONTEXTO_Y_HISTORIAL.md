# Contexto Completo, Historial de Decisiones y Especificaciones

## 1. Origen y Objetivo del Proyecto
Herramienta portÃ¡til (ejecutable desde USB o carpeta local) para tÃ©cnicos de soporte TI en sedes de **Universidad Norbert Wiener** e **Instituto CarriÃ³n**.
El flujo operativo consta de dos fases integradas en una interfaz grÃ¡fica de dos pestaÃ±as:
1. **PestaÃ±a 1 (RecolecciÃ³n en sitio):** Escanea el equipo actual, clasifica su ubicaciÃ³n, permite editar campos con alertas visuales, guarda `<HOSTNAME>.<DOMINIO>.txt` en subcarpetas por categorÃ­a/Ã¡rea y audita cambios frente a escaneos previos.
2. **PestaÃ±a 2 (ConsolidaciÃ³n y Nube):** Lee todos los `.txt` de las subcarpetas, permite editar celdas en un `DataGridView`, exporta un `.xlsx` nativo multi-pestaÃ±a (`ADMINISTRATIVOS`, `AULAS`, `LABORATORIO`, `TODOS`) y copia filas sin encabezados al portapapeles (`TSV`) para pegar directamente con `Ctrl + V` en el inventario maestro en la nube.

## 2. Problemas Resueltos Durante el Desarrollo (Lecciones Aprendidas)
- **EliminaciÃ³n de `wmic`:** Reemplazado por clases CIM/WMI (`Win32_ComputerSystem`, `Win32_BIOS`, `Win32_BaseBoard`, `Win32_SystemEnclosure`, `Win32_PhysicalMemory`, `MSFT_PhysicalDisk`, `WmiMonitorID`).
- **Valores invÃ¡lidos / relleno de fÃ¡brica:** Equipos ensamblados devuelven `Default string` o `To be filled by O.E.M.`, y algunos monitores secundarios devuelven `"1"` o `"00000000"` en su serie EDID. La funciÃ³n `CleanValue(..., isSerial: true)` descarta cadenas menores a 4 caracteres o de dÃ­gitos repetidos y marca `(validar presencialmente)` resaltando la celda en amarillo.
- **Respaldo de Serie en Placa Base:** Si `Win32_BIOS.SerialNumber` no es vÃ¡lido, se consulta `Win32_BaseBoard.SerialNumber` antes de pedir validaciÃ³n presencial.
- **ExclusiÃ³n de unidades USB:** `MSFT_PhysicalDisk` filtra `BusType != 7` (USB) para no listar la memoria USB del tÃ©cnico como disco duro del equipo.
- **Perfiles de Usuario y Active Directory:** Se lee `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` filtrando SIDs `S-1-5-21-*` y `S-1-12-1-*`, traduciendo el SID a `DOMINIO\usuario` y consultando Active Directory vÃ­a `DirectorySearcher` (`displayName`, `mail`, `userPrincipalName`).
- **Bloqueo de `.exe` por Smart App Control:** Al compilar un `.exe` con `csc.exe` sin firma digital, Windows 11 bloqueÃ³ su ejecuciÃ³n (`InvalidOperationException: Una directiva de Control de aplicaciones bloqueÃ³ este archivo`). Se resolviÃ³ ejecutando C# nativo en memoria desde `.bat` y ocultando la consola con `ShowWindow(GetConsoleWindow(), 0)`.
- **Error `UnauthorizedAccessException` en raÃ­z de unidad (`D:\`):** `Directory.GetFiles` con `SearchOption.AllDirectories` fallaba al intentar leer `D:\System Volume Information`. Se reemplazÃ³ por `GetInventoryTxtFiles()`, que solo revisa el directorio raÃ­z (`TopDirectoryOnly`) y las subcarpetas `ADMINISTRATIVOS`, `AULAS` y `LABORATORIO`.

## 3. Estructura Exacta de Columnas del Excel Maestro
1. `TIPO` (`PC` o `LAPTOP`)
2. `PISO` (`1`, `2`, `3`, `4`, `SÃ“TANO ANEXO`, etc.)
3. `ESTADO` (`OPERATIVO`)
4. `MARCA` (`HP`, `LENOVO`, `DELL`, etc.)
5. `MODELO` (limpio sin prefijo de marca redundante, ej. `ProBook 450 G10`, `Pro Mini 400 G9`, `ThinkCentre M70q Tiny`)
6. `SERIE`
7. `PROCESADOR`
8. `RAM` (ej. `32 GB`, `8 GB`)
9. `DISCO DURO` (normalizado comercialmente: `500 GB`, `512 GB`, `1 TB`, `256 GB`)
10. `MAC ADDRESS` (formato con dos puntos en mayÃºsculas: `24:FB:E3:C1:37:EE`)
11. `HOST NAME`
12. `MONITOR-MODELO` (vacÃ­o en `LAPTOP`)
13. `SERIE MONITOR` (vacÃ­o en `LAPTOP`)
14. `AREA` (ej. `SAE`, `VENTAS`, `SOPORTE TÃ‰CNICO`, `AULA 101`, `LABORATORIO DE COMPUTO 100`)
15. `REMACHADO / CADENA DE SEGURIDAD`
16. `AULA / LAB / ADMINISTRATIVO` (`ADMINISTRATIVO` para administrativos, o el nombre del aula/laboratorio)
17. `FECHA DE INVENTARIO` (`yyyy-MM-dd`)
18. `ORGANIZACIÃ“N` (`IDAC` para CarriÃ³n, `UPNW` u otra sigla configurable para Wiener)
19. `ANTIVIRUS` (`SÃ`)
20. `NOMBRE Y APELLIDO DE USUARIO` (`NOMBRE 1/NOMBRE 2` o `DOCENTE`)
21. `CORREO DE USUARIO` (`correo1@dominio/correo2@dominio`)
22. `ABSOLUTE` (`SÃ`)
23. `HP INSIGHTS` (`SÃ` para HP, `N/A` para otras marcas)
24. `CONTRATO` (vacÃ­o para ediciÃ³n manual)
25. `AÃ‘O F.` (vacÃ­o para ediciÃ³n manual)
26. `TECNICO RESPONSABLE` (`PRIMER_NOMBRE PRIMER_APELLIDO/PRIMER_NOMBRE PRIMER_APELLIDO`)
27. `OBSERVACIÃ“N` *(Solo en pestaÃ±a ADMINISTRATIVOS y TODOS)*

## 4. Mejoras Futuras / Backlog Propuesto
- DetecciÃ³n real en Windows de los servicios/agentes de **Antivirus** (`root\SecurityCenter2`), **Absolute** (`rpcnet`) y **HP Insights** en lugar de valores por defecto.
- ImportaciÃ³n del archivo Excel maestro descargado de la nube (`CARRION SJL.xlsx` o equivalente de Wiener) para cruzar datos y resaltar equipos nuevos vs. modificados.
- Soporte para registrar mÃºltiples monitores en puestos administrativos con doble pantalla.
- Escaneo remoto en red LAN/Dominio por rango de IPs o lista de hostnames.