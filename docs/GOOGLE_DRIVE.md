# Google Drive: sedes, respaldo y equipos con la USB bloqueada

## Estructura en Drive

```
Inventario TI - Reportes/              <- en el Drive del responsable
├── CARRION/
│   ├── SJL/                           <- compartida (Editor) solo con los técnicos de SJL
│   │   ├── Respaldo/                  <- copia exacta de la USB de la sede
│   │   └── Pendientes/                <- reportes de equipos con la USB bloqueada
│   │       └── Importados/            <- los que ya se incorporaron a la USB
│   ├── SJM/  SARMIENTO/  LOS OLIVOS/  SAN LUIS/  MENDIOLA/
└── WIENER/
    └── LOCAL 1/  LOCAL 2/  LOCAL 4/  LOCAL 5/  LIMA NORTE/
```

Cada técnico solo ve la carpeta de su sede. El programa reconoce las carpetas por una etiqueta interna (por ejemplo `CARRION/SJL`), así que **no hay que renombrarlas ni moverlas** a mano.

## Menú Google Drive del programa

| Opción | Para qué |
|---|---|
| **Subir último reporte (equipo con USB bloqueada)** | Envía el `.txt` a **Pendientes** de la sede. El programa también lo ofrece al presionar GUARDAR cuando no corre desde una USB. |
| **Importar pendientes de la sede** | Trae los pendientes a la USB con la comparación campo por campo, los mueve a **Importados** y actualiza el **Respaldo**. |
| **Respaldar todo en la nube** | Deja **Respaldo** igual a la USB: reportes vigentes, historial con fecha, Excel consolidado y `config_inventario.json`. Lo que ya no está en la USB va a la papelera de Drive, donde se puede recuperar durante 30 días. |
| **Elegir o cambiar la sede de esta USB** | La sede se guarda en `config_inventario.json`. Si la cuenta solo tiene acceso a una sede, se elige sola. |
| **Administrar sedes y técnicos...** | Solo para el responsable. Ver la sección 3. |

La sesión de Google solo dura mientras el programa está abierto: no se guarda nada en el equipo. Si un técnico inició sesión en el navegador de un equipo ajeno, debe cerrarla al terminar.

## 1. Proyecto de Google Cloud (una vez)

1. Entra a <https://console.cloud.google.com/> y crea un proyecto (por ejemplo `Inventario TI`).
2. **APIs y servicios > Biblioteca > Google Drive API > Habilitar**.
3. **Google Auth Platform** (o **Pantalla de consentimiento de OAuth**):
   - **Información de la app:** nombre `Inventario TI`.
   - **Público:** Externo.
   - **Estado de publicación:** Prueba.
   - **Usuarios de prueba:** agrega tu Gmail **y el de cada técnico**, hasta 100.
   - **Acceso a los datos:** agrega `https://www.googleapis.com/auth/drive`.
4. **Clientes > Crear cliente > App de escritorio**. Luego **Descargar JSON** y guárdalo como `build\google_oauth.local.json`. Ese archivo no se sube a GitHub.
5. `Empaquetar_Release.bat` debe mostrar `[OK] Credencial de Google Drive incluida en la compilacion.`

## 2. Crear las sedes (una vez)

1. En tu PC, abre **Google Drive > Administrar sedes y técnicos...** e inicia sesión.
2. Si no existe la carpeta **Inventario TI - Reportes**, el programa ofrece crearla.
3. La primera vez se crean todas las sedes por defecto, cada una con **Respaldo** y **Pendientes**.

## 3. Técnicos de cada sede

En **Administrar sedes y técnicos...**:

1. Elige la sede.
2. Usa **Agregar técnico...** y escribe su Gmail. Queda como **Editor** de esa sede y Google le envía una invitación por correo.
3. Agrega ese mismo Gmail en **Usuarios de prueba** del proyecto de Google Cloud (paso 1.3). Si no, Google le bloqueará el inicio de sesión.
4. Para revocar el acceso, usa **Quitar acceso**.

Con **Agregar sede...** puedes crear sedes nuevas: indicas la institución y el nombre.

## Qué verá cada persona al iniciar sesión

- **"Google no verificó esta app":** es normal en un proyecto personal en modo Prueba. Se continúa con **Avanzado > Ir a Inventario TI (no seguro)**.
- **Permiso para ver, editar y eliminar archivos de Google Drive:** Google lo pide así para poder trabajar en carpetas compartidas. El programa solo usa las carpetas del inventario.

## Limitación de Drive con cuentas personales

En Google Drive, **solo el dueño de un archivo puede mandarlo a la papelera**. Los archivos que sube un técnico son suyos. Si otra persona respalda o importa, el programa primero intenta quitarlos de la carpeta. Si tampoco puede:

- al **importar**, recuerda ese reporte para no traerlo otra vez;
- al **respaldar**, lo indica en el resumen ("No se pudo quitar…").

## Problemas frecuentes

| Mensaje | Solución |
|---|---|
| "Esta copia del programa no tiene configurada la conexión con Google Drive" | Se compiló sin `build\google_oauth.local.json`. Usa el programa del release. |
| "La cuenta … no tiene acceso a ninguna carpeta de sede" | El responsable debe agregar ese Gmail a su sede (sección 3). |
| `access_denied` / "acceso bloqueado" | El Gmail no está en **Usuarios de prueba**, o la persona canceló el permiso. |
| "Google Drive API has not been used in project..." | Falta habilitar la Google Drive API (paso 1.2). |
