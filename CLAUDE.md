# CLAUDE.md - Sistema de Inventario y Auditoría TI

## Descripción General
Aplicación de escritorio Windows Forms escrita en **C# (.NET Framework 4.x)** para el levantamiento, auditoría y consolidación a Excel del inventario de equipos de cómputo de **Universidad Norbert Wiener** e **Instituto Carrión**.

## Arquitectura y Restricciones Técnicas Críticas (NO ROMPER)
1. **Dos vías de ejecución del MISMO `src/InventarioApp.cs` (ambas deben seguir funcionando):**
   - **Principal — `InventarioTI.exe`:** generado con `Compilar_Exe.bat` (`csc.exe` de .NET Framework 4.x, `/codepage:65001`, manifiesto `src/app.manifest` con `asInvoker`: no requiere administrador, verificado que todas las consultas funcionan como usuario estándar). Entrada: `Program.Main()`.
     - Un `.exe` sin firma digital lo bloquea Smart App Control (PC personales) o el antivirus **aunque se ejecute como administrador**. En equipos de la institución (Kaspersky) debe aprobarse vía Seguridad TI (lista blanca por hash SHA-256 o, si se consigue, por certificado de firma de código). Cada recompilación cambia el hash.
     - **Nunca** intentar evadir Smart App Control / Kaspersky (ofuscación, empaquetadores, desactivarlos por script).
   - **Credencial de Google Drive:** `Compilar_Exe.bat` (y el empaquetador) compilan `obj\InventarioApp.build.cs`, que genera `build\preparar_fuente.ps1` reemplazando los marcadores `__GOOGLE_CLIENT_ID__` / `__GOOGLE_CLIENT_SECRET__` con `build\google_oauth.local.json`. Ese archivo y `obj/` **nunca se versionan** (GitHub bloquea credenciales); en `src/` quedan siempre los marcadores. Sin el archivo, Google Drive aparece como "no configurado".
   - **Respaldo — `Iniciar_Inventario.bat`:** compila y ejecuta en memoria con `Add-Type` en PowerShell (`-Sta`) y llama a `Program.StartApp()`. Se usa si el `.exe` está bloqueado en algún equipo.
   - Si se agrega una referencia a un ensamblado, actualizarla en `Compilar_Exe.bat`, `Iniciar_Inventario.bat`, la cabecera del `.bat` autónomo en `build/empaquetar_release.ps1` y el comando de verificación.
   - **Distribución (releases):** `Empaquetar_Release.bat` genera `dist\InventarioTI_v<versión>.zip` con solo 2 archivos para la USB/SSD: `InventarioTI.exe` + `Iniciar_Inventario.bat` **autónomo** (lleva el código C# embebido tras el marcador `//###CODIGO_CSHARP###`; no necesita la carpeta `src`). Ese `.bat` se genera siempre desde `src/InventarioApp.cs`: nunca editarlo a mano. `dist/` no se versiona; el ZIP se sube como asset del release de GitHub (repo **público** `aarneth/inventario-ti`; se hizo público para que el programa consulte las actualizaciones sin token: **nunca** subir contraseñas, tokens ni datos del inventario).
   - **Actualización automática:** al abrir (opción `Ayuda > Buscar actualizaciones al iniciar`, activada por defecto, guardada en `config_inventario.json` como `BuscarActualizaciones`) consulta `releases/latest` del repo; si hay versión mayor muestra las novedades y, si el técnico acepta, descarga `InventarioTI_v*.zip`, verifica el SHA-256 (`digest` de GitHub), renombra el `.exe` en ejecución a `InventarioTI.exe.old` (se borra al abrir la versión nueva), copia el `.exe` y el `.bat` nuevos y reabre el programa. Por eso **todo release debe llevar el asset `InventarioTI_v<versión>.zip`** con esos 2 archivos. No se actualiza la carpeta del proyecto (con `src\`) ni el `.bat` de desarrollo.
   - La **cabecera** del `.bat` autónomo (`build/empaquetar_release.ps1`) debe ser idéntica entre versiones: la actualización reemplaza el `.bat` mientras `cmd.exe` lo ejecuta.
   - **Versión única:** `[assembly: AssemblyVersion]` en `src/InventarioApp.cs` (el título de la ventana la lee en tiempo de ejecución). `src/app.manifest` debe tener la misma versión; el empaquetador falla si no coinciden. Tag de release = `v<Mayor>.<Menor>.<Parche>`.
2. **Compatibilidad estricta con C# 5:**
   - El compilador integrado de .NET Framework 4.x en Windows (`Add-Type`) soporta hasta **C# 5**.
   - **PROHIBIDO** usar sintaxis de C# 6+ (interpolación `$"..."`, operador `?.`, `nameof()`, pattern matching `is Type x`, expresiones lambda en propiedades `=>`, `record`, nullable reference types). Usar siempre `string.Format()`, comprobaciones explícitas `!= null` y bloques tradicionales.
3. **Prohibido usar `wmic.exe`:**
   - En compilaciones recientes de Windows 11 `wmic` fue eliminado. Toda consulta se realiza vía `System.Management` (CIM/WMI), `Microsoft.Win32` (Registro), `System.Net.NetworkInformation` y `System.DirectoryServices` (LDAP Active Directory).
4. **Rutas Seguras y Portabilidad USB:**
   - Usar siempre `INV_BASE_DIR` (o `AppDomain.CurrentDomain.BaseDirectory`) como raíz para guardar `config_inventario.json`, subcarpetas y `.xlsx`.
   - Al buscar `.txt` recursivamente, **nunca** usar `Directory.GetFiles(..., SearchOption.AllDirectories)` sobre la raíz de una unidad (`D:\`, USB), ya que lanza `UnauthorizedAccessException` al tocar `System Volume Information`. Usar siempre `GetInventoryTxtFiles()`.

## Reglas de Negocio (Wiener / Carrión)
- **Nomenclatura de Hostname:** `[W|C][Sede][PC|LP][AD|AU|LB][Área/Aula][Correlativo]` (ej. `C05LPADSAE01`, `W05PCADST01`, `C05PCAU10101`, `C05PCLB10001`).
- Los dígitos correlativos finales (`01`, `02`, `03`...) indican cantidad de equipos en el mismo ambiente y **se ignoran** al crear la subcarpeta de destino (ej. `ADMINISTRATIVOS\SAE\`, `AULAS\AULA 101\`).
- **Organización:** Prefijo `C` = `IDAC` (Instituto Carrión); prefijo `W` = `UPNW` (Universidad Norbert Wiener, editable en UI).
- **Esquema de Exportación Excel (`.xlsx` OpenXML nativo sin Office) y Portapapeles (`TSV`):**
  - `ADMINISTRATIVOS`: **27 columnas** (incluye `OBSERVACIÓN` al final).
  - `AULAS` y `LABORATORIO`: **26 columnas** (omiten `OBSERVACIÓN`).
  - Múltiples usuarios en un mismo equipo se unen con `/` en MAYÚSCULAS (`USUARIO 1/USUARIO 2`) y sus correos de AD con `/` en minúsculas (`correo1@dominio/correo2@dominio`).
  - **Usuarios (`BuildUsuariosExcel()`):** se ignoran las cuentas **locales** de soporte (cuenta o nombre con "soporte") y la cuenta `soporte.ti`; otras cuentas locales sí cuentan. Cuentas que empiezan con `doc` = `DOCENTE` y con `alu` = `ALUMNO` (doccarrion, alucarrion y equivalentes UPNW). `CORREO` solo lleva correos de usuarios reales; `N/A` si todos son DOCENTE/ALUMNO. Sin usuarios: AULAS/LABORATORIO = `DOCENTE` + `N/A`; ADMINISTRATIVOS = vacío.
  - **MODELO (`CleanModeloExcel()`):** solo el modelo comercial, sin marca, sin código entre paréntesis, sin tamaño de pantalla ni tipo de chasis (ej. `Pro Mini 400 G9`, `ProBook 450 G10`). En Lenovo se usa el nombre entre paréntesis. El `.txt` conserva el modelo completo.
  - **REMACHADO / CADENA (`NormalizeSeguridad()`):** `CON REMACHE/CON CADENA`, `CON REMACHE/SIN CADENA`, `SIN REMACHE/SIN CADENA`, `CADENA DE SEGURIDAD` (laptops). Los valores antiguos (`REMACHE Y CADENA`, `REMACHE / SIN CADENA`) se convierten al consolidar y al abrir el reporte.
  - **Tipo de equipo:** solo `PC` o `LAPTOP` (en el `.txt`, la pestaña 1 y el Excel), calculado con `NormalizeTipoEquipo()`: `LAPTOP` si el hostname tiene `LP` o el chasis es portátil (Laptop/Notebook/Convertible/Tablet); todo lo demás (torre, Mini PC, All-in-One, no identificado) = `PC`.
  - En `LAPTOP`, las columnas `MONITOR-MODELO` y `SERIE MONITOR` = `N/A`.
  - **ANTIVIRUS / ABSOLUTE / HP INSIGHTS** salen de la detección real (`ScanSecuritySoftware()`, sin admin) guardada en el `.txt` como `Antivirus`, `Absolute` y `HP Insights`:
    - `ANTIVIRUS` = `SÍ` **solo si es Kaspersky** (`CalcAntivirusCol()`); Defender u otro = `NO`.
    - `ABSOLUTE` = `SÍ`/`NO` según el agente (`CalcAgentCol()`).
    - `HP INSIGHTS` se calcula siempre con `CalcHpInsights(marca, agente)`: otras marcas = `NO`; HP = `SÍ`/`NO` según el agente. Al editar `MARCA` en la tabla se recalcula vía `TableTodos_ColumnChanged` (usa `hpAgentByFile`); `OBSERVACIÓN` **no** se modifica.
    - Reportes sin esas líneas (versiones anteriores) y filas de `+ Fila Manual` = `NO VERIFICADO`.
  - Ya **no** existe la observación `LENOVO SIN INSIGHT` (decisión del usuario).
- **Técnicos Responsables:** Se registran en MAYÚSCULAS usando únicamente **PRIMER NOMBRE y PRIMER APELLIDO** separados por `/` (ej. `ALVARO SORIANO/AARON GONZALES`) y se persisten en `config_inventario.json`.

## Gestión de Cambios (reemplazo de monitor, RAM, disco, CPU, equipo)
- **Formato `.txt`:** se lee y escribe solo con `ParseReport()` / `ReportToLines()` (clase `InventoryReport`). No armar líneas a mano. Las correcciones manuales por columna del Excel se guardan al final como `Ajuste Manual      : COLUMNA = valor` y tienen prioridad al consolidar.
- **Pestaña 1:** el botón **Abrir Reporte Existente** carga un `.txt` en el formulario para corregirlo. Al **GUARDAR**, `FindExistingReport()` busca el reporte vigente del hostname en **todas** las carpetas y `ComputeReportDiffs()` compara **campo por campo**: la IP, la puerta de enlace y el DNS **no** se comparan (cambian por DHCP); la MAC sí. El diálogo muestra Campo | Antes | Ahora | Usar.
  - "Guardar y archivar" copia el reporte **ANTERIOR** como `<HOST>.<DOM>_yyyyMMdd_HHmmss.txt` y deja el nuevo como vigente. Los archivos con fecha nunca entran a la consolidación.
  - Si cambian la Categoría o el Área, el reporte se mueve a la carpeta nueva y se borra de la anterior.
  - Las filas de `Ajuste Manual` aparecen en amarillo y, por defecto, **se conservan** ("Antes").
- **Pestaña 2:** "Guardar en .txt" persiste las ediciones de la tabla como `Ajuste Manual` (columna distinta del valor calculado = ajuste; igual = se elimina el ajuste). Hay aviso de cambios sin guardar al recargar, cambiar de institución o cerrar. Las filas manuales y las eliminadas solo afectan a la exportación.
- **Exportar Excel:** si ya existe `Inventario_Consolidado_*.xlsx`, `TryReadPreviousExport()` lee su hoja `TODOS` (también si se guardó después con Excel: sharedStrings) y compara por `HOST NAME`, sin comparar `FECHA DE INVENTARIO`.
  - Opciones del diálogo: aceptar todo lo nuevo, mantener todo lo del Excel, o elegir campo por campo.
  - "Mantener dato del Excel" se guarda en el `.txt` como `Ajuste Manual`, para que no vuelva a preguntar.
  - Equipos nuevos: se agregan. Equipos que ya no tienen `.txt`: se pregunta si se conservan.
- **Equipos con USB bloqueada:** el programa se ejecuta en ese equipo desde una carpeta de red o descargado del release; el `.txt` se trae por red/correo/Teams/OneDrive y se incorpora con `Archivo > Importar reportes (.txt)` o `Importar carpeta de reportes` (`ImportReports()`): reporte nuevo = se ubica en `CATEGORÍA\ÁREA`; equipo existente = mismo diálogo de comparación campo por campo (`ShowFieldDiffDialog` + `ApplyReportSave`); los archivos de historial con fecha y los `.txt` que no son reportes se ignoran. `Archivo > Abrir carpeta del último reporte` abre el Explorador en el último `.txt` escrito.
- **Google Drive (`docs/GOOGLE_DRIVE.md`, menú *Google Drive*):** OAuth de app de escritorio con PKCE y redirección a `127.0.0.1` (`TcpListener`, sin admin); cada técnico inicia sesión con **su** cuenta (proyecto personal en modo Prueba, técnicos como usuarios de prueba, permiso `auth/drive`) y el token **solo vive en memoria**.
  - Estructura: `Inventario TI - Reportes/<INST>/<SEDE>/{Respaldo, Pendientes/Importados}`. Las carpetas llevan `properties` (`invTI` = raiz/inst/sede/respaldo/pendientes, `invKey` = `CARRION/SJL`) y se buscan por esas propiedades, no por la ruta: el técnico solo tiene compartida su sede. Sedes por defecto en `SEDES_POR_DEFECTO`; se agregan desde la ventana de administración.
  - La sede de cada USB se guarda en config (`SedeDrive`); si la cuenta ve una sola sede se elige sola.
  - **Pendientes:** subida desde equipos con USB bloqueada (al GUARDAR si no corre desde unidad extraíble, `OfferDriveUploadAfterSave`; `PreguntarSubirDrive`). **Importar:** `ImportReports()` y mover a `Importados`; si no se puede mover (archivo de otro técnico) se recuerda en `DriveImportados`; luego sincroniza el Respaldo.
  - **Respaldo** (`SyncBackupToDrive`, solo con botón): copia exacta de la USB (txt vigentes + historial de las 3 categorías, `Inventario_Consolidado*.xlsx`, `config_inventario.json`), compara por MD5 y manda a la papelera lo que ya no está. En Drive personal solo el dueño de un archivo puede borrarlo: `DriveRemove` intenta papelera y luego quitarlo de la carpeta, y avisa si no puede.
  - **Administrar sedes y técnicos** (`ShowDriveAdmin`, dueño de la raíz): crea la estructura, agrega sedes y comparte/quita la sede (permiso Editor, con correo de invitación de Google).
- **Layout:** el contenido de cada pestaña se construye con su tamaño de diseño (1156x650) **antes** de agregarla al `TabControl`; si no, los controles anclados abajo (GUARDAR, EXPORTAR) quedan fuera de la vista.

## Comandos de Prueba y Verificación
- Compilar el ejecutable (muestra el SHA-256 para Kaspersky): `.\Compilar_Exe.bat` (agregar `/nopause` en ejecución no interactiva)
- Generar paquete de release (compila el `.exe`, crea el `.bat` autónomo y el ZIP, muestra los SHA-256): `.\Empaquetar_Release.bat` (`/nopause` en ejecución no interactiva)
- Ejecutar aplicación: `.\InventarioTI.exe` o, como respaldo, `.\Iniciar_Inventario.bat`
- Verificar sintaxis C# 5 rápida sin abrir ventana:
  `powershell -NoProfile -Command "$c = Get-Content src\InventarioApp.cs -Raw -Encoding UTF8; Add-Type -TypeDefinition $c -ReferencedAssemblies @('System.dll','System.Core.dll','System.Data.dll','System.Drawing.dll','System.Windows.Forms.dll','System.Management.dll','System.DirectoryServices.dll','System.IO.Compression.dll','System.IO.Compression.FileSystem.dll','System.Web.Extensions.dll','System.Xml.dll')"`