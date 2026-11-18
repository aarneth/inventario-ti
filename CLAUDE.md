# CLAUDE.md - Sistema de Inventario y AuditorÃ­a TI

## DescripciÃ³n General
AplicaciÃ³n de escritorio Windows Forms escrita en **C# (.NET Framework 4.x)** para el levantamiento, auditorÃ­a y consolidaciÃ³n a Excel del inventario de equipos de cÃ³mputo de **Universidad Norbert Wiener** e **Instituto CarriÃ³n**.

## Arquitectura y Restricciones TÃ©cnicas CrÃ­ticas (NO ROMPER)
1. **Dos vías de ejecución del MISMO `src/InventarioApp.cs` (ambas deben seguir funcionando):**
   - **Principal — `InventarioTI.exe`:** generado con `Compilar_Exe.bat` (`csc.exe` de .NET Framework 4.x, `/codepage:65001`, manifiesto `src/app.manifest` con `asInvoker`: no requiere administrador, verificado que todas las consultas funcionan como usuario estándar). Entrada: `Program.Main()`.
     - Un `.exe` sin firma digital lo bloquea Smart App Control (PC personales) o el antivirus **aunque se ejecute como administrador**. En equipos de la institución (Kaspersky) debe aprobarse vía Seguridad TI (lista blanca por hash SHA-256 o, si se consigue, por certificado de firma de código). Cada recompilación cambia el hash.
     - **Nunca** intentar evadir Smart App Control / Kaspersky (ofuscación, empaquetadores, desactivarlos por script).
   - **Respaldo — `Iniciar_Inventario.bat`:** compila y ejecuta en memoria con `Add-Type` en PowerShell (`-Sta`) y llama a `Program.StartApp()`. Se usa si el `.exe` está bloqueado en algún equipo.
   - Si se agrega una referencia a un ensamblado, actualizarla en **ambos** `.bat` y en el comando de verificación.
2. **Compatibilidad estricta con C# 5:**
   - El compilador integrado de .NET Framework 4.x en Windows (`Add-Type`) soporta hasta **C# 5**.
   - **PROHIBIDO** usar sintaxis de C# 6+ (interpolaciÃ³n `$"..."`, operador `?.`, `nameof()`, pattern matching `is Type x`, expresiones lambda en propiedades `=>`, `record`, nullable reference types). Usar siempre `string.Format()`, comprobaciones explÃ­citas `!= null` y bloques tradicionales.
3. **Prohibido usar `wmic.exe`:**
   - En compilaciones recientes de Windows 11 `wmic` fue eliminado. Toda consulta se realiza vÃ­a `System.Management` (CIM/WMI), `Microsoft.Win32` (Registro), `System.Net.NetworkInformation` y `System.DirectoryServices` (LDAP Active Directory).
4. **Rutas Seguras y Portabilidad USB:**
   - Usar siempre `INV_BASE_DIR` (o `AppDomain.CurrentDomain.BaseDirectory`) como raÃ­z para guardar `config_inventario.json`, subcarpetas y `.xlsx`.
   - Al buscar `.txt` recursivamente, **nunca** usar `Directory.GetFiles(..., SearchOption.AllDirectories)` sobre la raÃ­z de una unidad (`D:\`, USB), ya que lanza `UnauthorizedAccessException` al tocar `System Volume Information`. Usar siempre `GetInventoryTxtFiles()`.

## Reglas de Negocio (Wiener / CarriÃ³n)
- **Nomenclatura de Hostname:** `[W|C][Sede][PC|LP][AD|AU|LB][Ãrea/Aula][Correlativo]` (ej. `C05LPADSAE01`, `W05PCADST01`, `C05PCAU10101`, `C05PCLB10001`).
- Los dÃ­gitos correlativos finales (`01`, `02`, `03`...) indican cantidad de equipos en el mismo ambiente y **se ignoran** al crear la subcarpeta de destino (ej. `ADMINISTRATIVOS\SAE\`, `AULAS\AULA 101\`).
- **OrganizaciÃ³n:** Prefijo `C` = `IDAC` (Instituto CarriÃ³n); prefijo `W` = `UPNW` (Universidad Norbert Wiener, editable en UI).
- **Esquema de ExportaciÃ³n Excel (`.xlsx` OpenXML nativo sin Office) y Portapapeles (`TSV`):**
  - `ADMINISTRATIVOS`: **27 columnas** (incluye `OBSERVACIÃ“N` al final).
  - `AULAS` y `LABORATORIO`: **26 columnas** (omiten `OBSERVACIÃ“N`).
  - MÃºltiples usuarios en un mismo equipo se unen con `/` en MAYÃšSCULAS (`USUARIO 1/USUARIO 2`) y sus correos de AD con `/` en minÃºsculas (`correo1@dominio/correo2@dominio`).
  - En `LAPTOP`, las columnas `MONITOR-MODELO` y `SERIE MONITOR` quedan vacÃ­as si solo usan pantalla integrada.
  - En `LENOVO`, `HP INSIGHTS` = `N/A` y `OBSERVACIÃ“N` = `LENOVO SIN INSIGHT`.
- **TÃ©cnicos Responsables:** Se registran en MAYÃšSCULAS usando Ãºnicamente **PRIMER NOMBRE y PRIMER APELLIDO** separados por `/` (ej. `ALVARO SORIANO/AARON GONZALES`) y se persisten en `config_inventario.json`.

## Comandos de Prueba y VerificaciÃ³n
- Compilar el ejecutable (muestra el SHA-256 para Kaspersky): `.\Compilar_Exe.bat` (agregar `/nopause` en ejecución no interactiva)
- Ejecutar aplicación: `.\InventarioTI.exe` o, como respaldo, `.\Iniciar_Inventario.bat`
- Verificar sintaxis C# 5 rÃ¡pida sin abrir ventana:
  `powershell -NoProfile -Command "$c = Get-Content src\InventarioApp.cs -Raw -Encoding UTF8; Add-Type -TypeDefinition $c -ReferencedAssemblies @('System.dll','System.Core.dll','System.Data.dll','System.Drawing.dll','System.Windows.Forms.dll','System.Management.dll','System.DirectoryServices.dll','System.IO.Compression.dll','System.IO.Compression.FileSystem.dll','System.Web.Extensions.dll','System.Xml.dll')"`