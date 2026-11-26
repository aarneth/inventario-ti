using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.DirectoryServices;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using System.Xml;
using Microsoft.Win32;

// Metadatos visibles en Propiedades > Detalles del .exe (ayuda a Seguridad TI a identificarlo en Kaspersky)
[assembly: AssemblyTitle("Sistema de Inventario y Auditoria TI")]
[assembly: AssemblyProduct("Inventario TI - Wiener / Carrion")]
[assembly: AssemblyDescription("Levantamiento y consolidacion de inventario de equipos de computo")]
[assembly: AssemblyVersion("1.4.0.0")]
[assembly: AssemblyFileVersion("1.4.0.0")]

namespace SistemaInventarioTI
{
    public class NetAdapterInfo
    {
        public string Description;
        public string IPv4;
        public string Gateway;
        public string DNS;
        public string MAC;
    }

    // Representacion estructurada de un reporte <HOSTNAME>.<DOMINIO>.txt
    public class InventoryReport
    {
        public static readonly string[] FieldKeys = new string[] {
            "Categoria Ubicacion", "Area / Ambiente", "Piso Ubicacion", "Seguridad Fisica",
            "Tipo de Equipo", "Marca", "Modelo", "Serie del Equipo", "Hostname", "Dominio / Grupo",
            "Sistema Operativo", "Procesador", "Memoria RAM", "Almacenamiento",
            "Antivirus", "Absolute", "HP Insights"
        };

        public Dictionary<string, string> Fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public List<string> Users = new List<string>();
        public List<NetAdapterInfo> Nets = new List<NetAdapterInfo>();
        public List<string> Monitors = new List<string>();
        // Correcciones manuales por columna del Excel (lineas "Ajuste Manual : COLUMNA = valor")
        public List<KeyValuePair<string, string>> Ajustes = new List<KeyValuePair<string, string>>();
        public string FechaAuditoria = "";
        public string UsuarioEjecutor = "";

        public string Get(string key)
        {
            string v;
            if (Fields.TryGetValue(key, out v) && v != null) return v;
            return "";
        }

        public void Set(string key, string value)
        {
            Fields[key] = value ?? "";
        }

        public string GetAjuste(string column)
        {
            foreach (KeyValuePair<string, string> kv in Ajustes)
            {
                if (string.Equals(kv.Key, column, StringComparison.OrdinalIgnoreCase)) return kv.Value;
            }
            return null;
        }

        public void SetAjuste(string column, string value)
        {
            Ajustes.RemoveAll(kv => string.Equals(kv.Key, column, StringComparison.OrdinalIgnoreCase));
            if (value != null) Ajustes.Add(new KeyValuePair<string, string>(column, value));
        }

        public static NetAdapterInfo CloneNet(NetAdapterInfo n)
        {
            NetAdapterInfo c = new NetAdapterInfo();
            c.Description = n.Description ?? "";
            c.IPv4 = n.IPv4 ?? "";
            c.Gateway = n.Gateway ?? "";
            c.DNS = n.DNS ?? "";
            c.MAC = n.MAC ?? "";
            return c;
        }

        public InventoryReport Clone()
        {
            InventoryReport c = new InventoryReport();
            foreach (KeyValuePair<string, string> kv in Fields) c.Fields[kv.Key] = kv.Value;
            c.Users.AddRange(Users);
            foreach (NetAdapterInfo n in Nets) c.Nets.Add(CloneNet(n));
            c.Monitors.AddRange(Monitors);
            c.Ajustes.AddRange(Ajustes);
            c.FechaAuditoria = FechaAuditoria;
            c.UsuarioEjecutor = UsuarioEjecutor;
            return c;
        }
    }

    public class ConfigModel
    {
        public string Tecnicos { get; set; }
        public string OrgWiener { get; set; }
        public Dictionary<string, string> Areas { get; set; }
        public Dictionary<string, string> Pisos { get; set; }
        // null (configuracion de versiones anteriores) = activado
        public bool? BuscarActualizaciones { get; set; }
        // false = no preguntar si se sube el reporte a Google Drive al guardar (null = preguntar)
        public bool? PreguntarSubirDrive { get; set; }
        // Sede de Google Drive de esta USB ("CARRION/SJL") y reportes de Pendientes ya importados que no se pudieron mover
        public string SedeDrive { get; set; }
        public List<string> DriveImportados { get; set; }
    }

    public class MainForm : Form
    {
        private string baseDir;
        private string configPath;
        private Dictionary<string, string> areaMap;
        private Dictionary<string, string> pisosMap;
        private Dictionary<string, string> pnpMonitorMap;
        private string tecnicosResponsables = "ALVARO SORIANO/AARON GONZALES";
        private string orgWienerGuardada = "UPNW";
        private string currentUserExec = "";
        private List<NetAdapterInfo> activeNets = new List<NetAdapterInfo>();
        // Correcciones manuales (Ajuste Manual) del reporte abierto en la pestana 1
        private List<KeyValuePair<string, string>> currentAjustes = new List<KeyValuePair<string, string>>();
        // Pestana 2, por ruta de .txt: valores calculados del escaneo (sin ajustes) y valores tal como se cargaron
        private Dictionary<string, string[]> calcByFile = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        private Dictionary<string, string[]> loadedByFile = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        // Pestana 2, por ruta de .txt: resultado de la deteccion del agente HP Insights (para recalcular al editar MARCA)
        private Dictionary<string, string> hpAgentByFile = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        // Pestana 1: resultado de la deteccion de software de seguridad del equipo escaneado o del reporte abierto
        private string secAntivirus = "";
        private string secAbsolute = "";
        private string secHpInsights = "";
        // Actualizaciones automaticas (ver region "Actualizaciones")
        private bool buscarActualizaciones = true;
        private bool cerrandoPorActualizacion = false;
        // Ultimo .txt escrito (para "Archivo > Abrir carpeta del ultimo reporte")
        private string lastSavedReportPath = null;

        private Label lblHeaderStats;
        private ToolStripStatusLabel lblStatusText;
        private ToolStripStatusLabel lblStatusCount;
        private TabControl tabs;

        // Pestana 1: Escaneo
        private ComboBox cmbCat;
        private TextBox txtPiso;
        private ComboBox cmbArea;
        private ComboBox cmbSeg;
        private TextBox txtTipo;
        private TextBox txtMarca;
        private TextBox txtModelo;
        private TextBox txtSerie;
        private TextBox txtHost;
        private TextBox txtDom;
        private TextBox txtSO;
        private TextBox txtCPU;
        private TextBox txtRAM;
        private TextBox txtDisk;
        private TextBox txtUsers;
        private TextBox txtMons;
        private RichTextBox rtbPreview;
        private bool suppressPreview = false;

        // Pestana 2: Consolidador Editable
        private ComboBox cmbInst;
        private TextBox txtOrgW;
        private ComboBox cmbFiltro;
        private TextBox txtTec;
        private DataGridView grid;
        private DataTable tableTodos;

        private readonly string[] headersAdm = new string[] {
            "TIPO", "PISO", "ESTADO", "MARCA", "MODELO", "SERIE", "PROCESADOR", "RAM", "DISCO DURO",
            "MAC ADDRESS", "HOST NAME", "MONITOR-MODELO", "SERIE MONITOR", "AREA",
            "REMACHADO / CADENA DE SEGURIDAD", "AULA / LAB / ADMINISTRATIVO", "FECHA DE INVENTARIO",
            "ORGANIZACI\u00D3N", "ANTIVIRUS", "NOMBRE Y APELLIDO DE USUARIO", "CORREO DE USUARIO",
            "ABSOLUTE", "HP INSIGHTS", "CONTRATO", "A\u00D1O F.", "TECNICO RESPONSABLE", "OBSERVACI\u00D3N"
        };

        public MainForm()
        {
            string envDir = Environment.GetEnvironmentVariable("INV_BASE_DIR");
            string rawDir = (!string.IsNullOrEmpty(envDir) ? envDir : AppDomain.CurrentDomain.BaseDirectory).Trim();
            try { baseDir = Path.GetFullPath(rawDir); }
            catch { baseDir = rawDir; }

            // Si no es la raiz del disco (ej. D:\), quitar la barra final
            if (baseDir.Length > 3)
                baseDir = baseDir.TrimEnd('\\');

            configPath = Path.Combine(baseDir, "config_inventario.json");

            InitMaps();
            LoadConfig();
            BuildUI();
        }

        // Buscador seguro que evita System Volume Information y solo revisa carpetas de inventario
        private List<FileInfo> GetInventoryTxtFiles()
        {
            List<FileInfo> result = new List<FileInfo>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1. Archivos .txt sueltos directamente en la carpeta actual (sin entrar a carpetas del sistema)
            try
            {
                DirectoryInfo rootDi = new DirectoryInfo(baseDir);
                foreach (FileInfo fi in rootDi.GetFiles("*.txt", SearchOption.TopDirectoryOnly))
                {
                    if (IsValidInventoryTxt(fi) && seen.Add(fi.FullName))
                        result.Add(fi);
                }
            }
            catch { }

            // 2. Archivos .txt dentro de las subcarpetas de inventario (ADMINISTRATIVOS, AULAS, LABORATORIO)
            string[] categorias = new string[] { "ADMINISTRATIVOS", "AULAS", "LABORATORIO" };
            foreach (string cat in categorias)
            {
                string catPath = Path.Combine(baseDir, cat);
                if (Directory.Exists(catPath))
                {
                    CollectTxtSafeRecursive(new DirectoryInfo(catPath), result, seen);
                }
            }

            return result;
        }

        private void CollectTxtSafeRecursive(DirectoryInfo di, List<FileInfo> result, HashSet<string> seen)
        {
            try
            {
                if ((di.Attributes & FileAttributes.ReparsePoint) != 0) return;
                string nameUp = di.Name.ToUpperInvariant();
                if (nameUp == "SYSTEM VOLUME INFORMATION" || nameUp == "$RECYCLE.BIN") return;

                foreach (FileInfo fi in di.GetFiles("*.txt", SearchOption.TopDirectoryOnly))
                {
                    if (IsValidInventoryTxt(fi) && seen.Add(fi.FullName))
                        result.Add(fi);
                }

                foreach (DirectoryInfo sub in di.GetDirectories())
                {
                    CollectTxtSafeRecursive(sub, result, seen);
                }
            }
            catch { }
        }

        private bool IsValidInventoryTxt(FileInfo fi)
        {
            try
            {
                if (Regex.IsMatch(fi.Name, @"^Consolidado", RegexOptions.IgnoreCase)) return false;
                if (Regex.IsMatch(fi.Name, @"_\d{8}_\d{6}\.txt$", RegexOptions.IgnoreCase)) return false;
                return true;
            }
            catch { return false; }
        }

        private Icon CreateMemoryAppIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                g.Clear(Color.FromArgb(37, 99, 235));
                using (Pen p = new Pen(Color.White, 2f))
                {
                    g.DrawRectangle(p, 5, 6, 22, 15);
                }
                g.FillRectangle(Brushes.White, 12, 22, 8, 3);
                g.FillRectangle(Brushes.White, 8, 25, 16, 2);
            }
            return Icon.FromHandle(bmp.GetHicon());
        }

        private void InitMaps()
        {
            areaMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                { "SAE", "SAE" },
                { "CV", "VENTAS" },
                { "JS", "JEFATURA" },
                { "SAD", "SAD" },
                { "BEP", "BIENESTAR" },
                { "MD", "MD" },
                { "TO", "T\u00D3PICO" },
                { "ST", "SOPORTE T\u00C9CNICO" },
                { "SSGG", "SERVICIOS GENERALES" }
            };

            pisosMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                { "SAE", "1" }, { "CV", "1" }, { "JS", "1" }, { "SAD", "2" },
                { "BEP", "2" }, { "MD", "3" }, { "TO", "3" }, { "ST", "4" },
                { "SSGG", "S\u00D3TANO ANEXO" }
            };

            pnpMonitorMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                { "AAC", "Acer" }, { "ACR", "Acer" }, { "AOC", "AOC" }, { "AUS", "ASUS" },
                { "BNQ", "BenQ" }, { "CMN", "Chimei Innolux" }, { "DEL", "Dell" }, { "ENC", "Eizo" },
                { "GBT", "Gigabyte" }, { "GSM", "LG" }, { "HPN", "HP" }, { "HWP", "HP" },
                { "IVM", "Iiyama" }, { "LEN", "Lenovo" }, { "LGD", "LG Display" }, { "MSI", "MSI" },
                { "NEC", "NEC" }, { "PHL", "Philips" }, { "SAM", "Samsung" }, { "SEC", "Samsung" },
                { "SNY", "Sony" }, { "TOS", "Toshiba" }, { "VSC", "ViewSonic" }
            };
        }

        private void LoadConfig()
        {
            if (!File.Exists(configPath)) return;
            try
            {
                string json = File.ReadAllText(configPath, Encoding.UTF8);
                JavaScriptSerializer ser = new JavaScriptSerializer();
                ConfigModel cfg = ser.Deserialize<ConfigModel>(json);
                if (cfg != null)
                {
                    if (!string.IsNullOrWhiteSpace(cfg.Tecnicos)) tecnicosResponsables = cfg.Tecnicos.Trim().ToUpper();
                    if (!string.IsNullOrWhiteSpace(cfg.OrgWiener)) orgWienerGuardada = cfg.OrgWiener.Trim().ToUpper();
                    if (cfg.Areas != null)
                    {
                        foreach (KeyValuePair<string, string> kv in cfg.Areas)
                            areaMap[kv.Key.ToUpper()] = kv.Value.ToUpper();
                    }
                    if (cfg.Pisos != null)
                    {
                        foreach (KeyValuePair<string, string> kv in cfg.Pisos)
                            pisosMap[kv.Key.ToUpper()] = kv.Value.ToUpper();
                    }
                    if (cfg.BuscarActualizaciones.HasValue) buscarActualizaciones = cfg.BuscarActualizaciones.Value;
                    if (cfg.PreguntarSubirDrive.HasValue) preguntarSubirDrive = cfg.PreguntarSubirDrive.Value;
                    if (!string.IsNullOrWhiteSpace(cfg.SedeDrive)) sedeDrive = cfg.SedeDrive.Trim();
                    if (cfg.DriveImportados != null) driveImportadosIds = new List<string>(cfg.DriveImportados);
                }
            }
            catch { }
        }

        private void SaveConfig()
        {
            try
            {
                ConfigModel cfg = new ConfigModel();
                cfg.Tecnicos = tecnicosResponsables;
                cfg.OrgWiener = orgWienerGuardada;
                cfg.Areas = areaMap;
                cfg.Pisos = pisosMap;
                cfg.BuscarActualizaciones = buscarActualizaciones;
                cfg.PreguntarSubirDrive = preguntarSubirDrive;
                cfg.SedeDrive = sedeDrive;
                // Solo los ultimos 500 (cada entrada es id|fecha de un archivo de Pendientes)
                cfg.DriveImportados = driveImportadosIds.Skip(Math.Max(0, driveImportadosIds.Count - 500)).ToList();

                JavaScriptSerializer ser = new JavaScriptSerializer();
                string json = ser.Serialize(cfg);
                File.WriteAllText(configPath, json, Encoding.UTF8);
            }
            catch { }
        }

        private void BuildUI()
        {
            // La version mostrada sale de AssemblyVersion (unica fuente; ver Empaquetar_Release.bat)
            Version ver = Assembly.GetExecutingAssembly().GetName().Version;
            this.Text = string.Format("Sistema de Inventario y Auditor\u00EDa TI v{0}.{1}.{2} (C# Nativo) - Wiener / Carri\u00F3n", ver.Major, ver.Minor, ver.Build);
            // +24 px de alto por la barra de menu, para que las pestanas conserven su tamano de diseno (1156x650)
            this.Size = new Size(1180, 814);
            this.MinimumSize = new Size(1050, 724);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Font = new Font("Segoe UI", 9F, FontStyle.Regular);
            this.BackColor = Color.FromArgb(241, 245, 249);
            try { this.Icon = CreateMemoryAppIcon(); } catch { }

            Panel pnlHeader = new Panel();
            pnlHeader.Dock = DockStyle.Top;
            pnlHeader.Height = 54;
            pnlHeader.BackColor = Color.FromArgb(15, 23, 42);

            Label lblTitle = new Label();
            lblTitle.Text = "SISTEMA DE INVENTARIO Y AUDITOR\u00CDA TI";
            lblTitle.Font = new Font("Segoe UI", 13F, FontStyle.Bold);
            lblTitle.ForeColor = Color.White;
            lblTitle.Location = new Point(16, 8);
            lblTitle.AutoSize = true;
            pnlHeader.Controls.Add(lblTitle);

            Label lblSub = new Label();
            lblSub.Text = "Universidad Norbert Wiener  |  Instituto Carri\u00F3n  \u2022  Motor CIM/WMI y Active Directory 100% Nativo";
            lblSub.Font = new Font("Segoe UI", 8.5F, FontStyle.Regular);
            lblSub.ForeColor = Color.FromArgb(148, 163, 184);
            lblSub.Location = new Point(18, 31);
            lblSub.AutoSize = true;
            pnlHeader.Controls.Add(lblSub);

            lblHeaderStats = new Label();
            lblHeaderStats.Text = "Carpeta activa: " + baseDir;
            lblHeaderStats.Font = new Font("Segoe UI Semibold", 9F);
            lblHeaderStats.ForeColor = Color.FromArgb(56, 189, 248);
            lblHeaderStats.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            lblHeaderStats.Location = new Point(650, 18);
            lblHeaderStats.Size = new Size(500, 22);
            lblHeaderStats.TextAlign = ContentAlignment.MiddleRight;
            pnlHeader.Controls.Add(lblHeaderStats);

            StatusStrip statusStrip = new StatusStrip();
            statusStrip.BackColor = Color.FromArgb(226, 232, 240);
            lblStatusText = new ToolStripStatusLabel("Listo.");
            lblStatusText.Spring = true;
            lblStatusText.TextAlign = ContentAlignment.MiddleLeft;
            lblStatusCount = new ToolStripStatusLabel("Equipos consolidados: 0");
            lblStatusCount.Font = new Font("Segoe UI Semibold", 8.5F);
            statusStrip.Items.Add(lblStatusText);
            statusStrip.Items.Add(lblStatusCount);

            tabs = new TabControl();
            tabs.Dock = DockStyle.Fill;
            tabs.Font = new Font("Segoe UI Semibold", 9.5F);

            TabPage tabScan = new TabPage("  1. Escanear y Auditar Equipo Actual  ");
            TabPage tabExcel = new TabPage("  2. Consolidar Tabla Editable y Exportar a Excel / Nube  ");
            tabScan.BackColor = Color.FromArgb(248, 250, 252);
            tabExcel.BackColor = Color.FromArgb(248, 250, 252);

            // Construir el contenido con el tamano de diseno ANTES de agregar las pestanas al TabControl:
            // los controles anclados abajo/derecha (botones GUARDAR, EXPORTAR...) calculan su posicion
            // respecto al tamano que tiene la pestana en ese momento.
            tabScan.Size = new Size(1156, 650);
            tabExcel.Size = new Size(1156, 650);
            BuildTabScan(tabScan);
            BuildTabExcel(tabExcel);

            tabs.TabPages.Add(tabScan);
            tabs.TabPages.Add(tabExcel);

            MenuStrip menu = new MenuStrip();
            menu.BackColor = Color.FromArgb(226, 232, 240);
            ToolStripMenuItem mnuArchivo = new ToolStripMenuItem("Archivo");
            ToolStripMenuItem mnuImpFiles = new ToolStripMenuItem("Importar reportes (.txt)...");
            mnuImpFiles.Click += delegate { ImportReportsFromFiles(); };
            ToolStripMenuItem mnuImpDir = new ToolStripMenuItem("Importar carpeta de reportes...");
            mnuImpDir.Click += delegate { ImportReportsFromFolder(); };
            ToolStripMenuItem mnuOpenDir = new ToolStripMenuItem("Abrir carpeta del \u00FAltimo reporte");
            mnuOpenDir.Click += delegate { OpenLastReportFolder(); };
            mnuArchivo.DropDownItems.Add(mnuImpFiles);
            mnuArchivo.DropDownItems.Add(mnuImpDir);
            mnuArchivo.DropDownItems.Add(new ToolStripSeparator());
            mnuArchivo.DropDownItems.Add(mnuOpenDir);
            menu.Items.Add(mnuArchivo);

            ToolStripMenuItem mnuDrive = new ToolStripMenuItem("Google Drive");
            ToolStripMenuItem mnuDriveUp = new ToolStripMenuItem("Subir \u00FAltimo reporte (equipo con USB bloqueada)");
            mnuDriveUp.Click += delegate { UploadReportToDrive(lastSavedReportPath); };
            ToolStripMenuItem mnuDriveImp = new ToolStripMenuItem("Importar pendientes de la sede");
            mnuDriveImp.Click += delegate { ImportFromDrive(); };
            ToolStripMenuItem mnuDriveBak = new ToolStripMenuItem("Respaldar todo en la nube");
            mnuDriveBak.Click += delegate { BackupToDriveMenu(); };
            ToolStripMenuItem mnuDriveSede = new ToolStripMenuItem("Cambiar sede de esta USB...");
            mnuDriveSede.Click += delegate { ChangeDriveSede(); };
            ToolStripMenuItem mnuDriveAdm = new ToolStripMenuItem("Administrar sedes y t\u00E9cnicos...");
            mnuDriveAdm.Click += delegate { ShowDriveAdmin(); };
            mnuDrive.DropDownItems.Add(mnuDriveUp);
            mnuDrive.DropDownItems.Add(mnuDriveImp);
            mnuDrive.DropDownItems.Add(mnuDriveBak);
            mnuDrive.DropDownItems.Add(new ToolStripSeparator());
            mnuDrive.DropDownItems.Add(mnuDriveSede);
            mnuDrive.DropDownItems.Add(mnuDriveAdm);
            mnuDrive.DropDownOpening += delegate {
                mnuDriveSede.Text = sedeDrive.Length > 0
                    ? "Cambiar sede de esta USB (actual: " + sedeDrive.Replace("/", " / ") + ")..."
                    : "Elegir sede de esta USB...";
            };
            menu.Items.Add(mnuDrive);

            ToolStripMenuItem mnuAyuda = new ToolStripMenuItem("Ayuda");
            ToolStripMenuItem mnuAcerca = new ToolStripMenuItem("Acerca de...");
            mnuAcerca.ShortcutKeys = Keys.F1;
            mnuAcerca.Click += delegate { ShowAboutDialog(); };
            ToolStripMenuItem mnuAutoUpd = new ToolStripMenuItem("Buscar actualizaciones al iniciar");
            mnuAutoUpd.CheckOnClick = true;
            mnuAutoUpd.Checked = buscarActualizaciones;
            mnuAutoUpd.CheckedChanged += delegate {
                buscarActualizaciones = mnuAutoUpd.Checked;
                SaveConfig();
            };
            ToolStripMenuItem mnuUpdNow = new ToolStripMenuItem("Buscar actualizaciones ahora");
            mnuUpdNow.Click += delegate { CheckForUpdatesManual(); };
            mnuAyuda.DropDownItems.Add(mnuUpdNow);
            mnuAyuda.DropDownItems.Add(mnuAutoUpd);
            mnuAyuda.DropDownItems.Add(new ToolStripSeparator());
            mnuAyuda.DropDownItems.Add(mnuAcerca);
            menu.Items.Add(mnuAyuda);

            this.Controls.Add(tabs);
            this.Controls.Add(pnlHeader);
            this.Controls.Add(statusStrip);
            // Se agrega al final para que quede arriba de la cabecera
            this.Controls.Add(menu);
            this.MainMenuStrip = menu;

            tabs.SelectedIndexChanged += delegate {
                if (tabs.SelectedIndex == 1) LoadTxtFilesIntoTable();
            };

            this.Shown += delegate {
                CleanupAfterUpdate();
                ScanCurrentHardware();
                UpdateTxtCounterBadge();
                if (buscarActualizaciones) CheckForUpdatesInBackground();
            };

            this.FormClosing += delegate(object s, FormClosingEventArgs ev) {
                if (cerrandoPorActualizacion) return;
                if (!ConfirmSaveOrDiscardGridChanges()) ev.Cancel = true;
            };
        }

        private void BuildTabScan(TabPage page)
        {
            GroupBox grpUbic = new GroupBox();
            grpUbic.Text = "1. Clasificaci\u00F3n de Ubicaci\u00F3n y Seguridad F\u00EDsica";
            grpUbic.Location = new Point(14, 10);
            grpUbic.Size = new Size(555, 128);
            grpUbic.BackColor = Color.White;
            page.Controls.Add(grpUbic);

            AddLabel(grpUbic, "Categor\u00EDa:", 14, 28, 75);
            cmbCat = new ComboBox();
            cmbCat.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbCat.Items.AddRange(new object[] { "ADMINISTRATIVOS", "AULAS", "LABORATORIO" });
            cmbCat.SelectedIndex = 0;
            cmbCat.Location = new Point(95, 25);
            cmbCat.Size = new Size(165, 24);
            cmbCat.SelectedIndexChanged += delegate { UpdatePreview(); };
            grpUbic.Controls.Add(cmbCat);

            AddLabel(grpUbic, "Piso:", 275, 28, 40);
            txtPiso = new TextBox();
            txtPiso.Location = new Point(320, 25);
            txtPiso.Size = new Size(218, 24);
            txtPiso.TextChanged += delegate { UpdatePreview(); };
            grpUbic.Controls.Add(txtPiso);

            AddLabel(grpUbic, "\u00C1rea / Aula:", 14, 60, 75);
            cmbArea = new ComboBox();
            cmbArea.Location = new Point(95, 57);
            cmbArea.Size = new Size(315, 24);
            cmbArea.TextChanged += delegate { UpdatePreview(); };
            grpUbic.Controls.Add(cmbArea);
            RefreshAreaCombo();

            Button btnAddArea = new Button();
            btnAddArea.Text = "+ Nueva Sigla";
            btnAddArea.Location = new Point(418, 56);
            btnAddArea.Size = new Size(120, 26);
            btnAddArea.BackColor = Color.FromArgb(224, 242, 254);
            btnAddArea.FlatStyle = FlatStyle.Flat;
            btnAddArea.Click += BtnAddArea_Click;
            grpUbic.Controls.Add(btnAddArea);

            AddLabel(grpUbic, "Seguridad:", 14, 93, 75);
            cmbSeg = new ComboBox();
            cmbSeg.Items.AddRange(new object[] {
                "CADENA DE SEGURIDAD",
                "CON REMACHE/CON CADENA",
                "CON REMACHE/SIN CADENA",
                "SIN REMACHE/SIN CADENA",
                "NINGUNO"
            });
            cmbSeg.SelectedIndex = 0;
            cmbSeg.Location = new Point(95, 90);
            cmbSeg.Size = new Size(443, 24);
            cmbSeg.TextChanged += delegate { UpdatePreview(); };
            grpUbic.Controls.Add(cmbSeg);

            GroupBox grpHw = new GroupBox();
            grpHw.Text = "2. Hardware, Usuarios y Monitores (Celdas amarillas = validar en sitio / editables)";
            grpHw.Location = new Point(14, 144);
            grpHw.Size = new Size(555, 445);
            grpHw.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left;
            grpHw.BackColor = Color.White;
            page.Controls.Add(grpHw);

            txtTipo   = AddEditableRow(grpHw, "Tipo de Equipo:", 24, 24, false);
            txtMarca  = AddEditableRow(grpHw, "Marca:", 52, 24, false);
            txtModelo = AddEditableRow(grpHw, "Modelo:", 80, 24, false);
            txtSerie  = AddEditableRow(grpHw, "Serie Equipo:", 108, 24, false);
            txtHost   = AddEditableRow(grpHw, "Hostname:", 136, 24, false);
            txtDom    = AddEditableRow(grpHw, "Dominio / Red:", 164, 24, false);
            txtSO     = AddEditableRow(grpHw, "Sist. Operativo:", 192, 24, false);
            txtCPU    = AddEditableRow(grpHw, "Procesador:", 220, 24, false);
            txtRAM    = AddEditableRow(grpHw, "Memoria RAM:", 248, 24, false);
            txtDisk   = AddEditableRow(grpHw, "Almacenamiento:", 276, 24, false);
            txtUsers  = AddEditableRow(grpHw, "Usuarios (1/l\u00EDn):", 306, 60, true);
            txtMons   = AddEditableRow(grpHw, "Monitores (1/l\u00EDn):", 372, 60, true);

            GroupBox grpPrev = new GroupBox();
            grpPrev.Text = "3. Vista Previa en Tiempo Real del Archivo <HOSTNAME>.<DOMINIO>.txt";
            grpPrev.Location = new Point(580, 10);
            grpPrev.Size = new Size(565, 579);
            grpPrev.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            grpPrev.BackColor = Color.White;
            page.Controls.Add(grpPrev);

            rtbPreview = new RichTextBox();
            rtbPreview.Location = new Point(12, 24);
            rtbPreview.Size = new Size(540, 542);
            rtbPreview.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            rtbPreview.Font = new Font("Consolas", 9.2F);
            rtbPreview.ReadOnly = true;
            rtbPreview.BackColor = Color.FromArgb(15, 23, 42);
            rtbPreview.ForeColor = Color.FromArgb(226, 232, 240);
            grpPrev.Controls.Add(rtbPreview);

            Button btnRescan = new Button();
            btnRescan.Text = "Re-escanear Hardware";
            btnRescan.Location = new Point(14, 598);
            btnRescan.Size = new Size(180, 42);
            btnRescan.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnRescan.BackColor = Color.FromArgb(226, 232, 240);
            btnRescan.FlatStyle = FlatStyle.Flat;
            btnRescan.Click += delegate { ScanCurrentHardware(); };
            page.Controls.Add(btnRescan);

            Button btnOpen = new Button();
            btnOpen.Text = "Abrir Reporte Existente (.txt)";
            btnOpen.Location = new Point(204, 598);
            btnOpen.Size = new Size(200, 42);
            btnOpen.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnOpen.BackColor = Color.FromArgb(254, 243, 199);
            btnOpen.FlatStyle = FlatStyle.Flat;
            btnOpen.Click += BtnOpenReport_Click;
            page.Controls.Add(btnOpen);

            Button btnSave = new Button();
            btnSave.Text = "GUARDAR REPORTE (.TXT) EN SUBCARPETA Y AUDITAR CAMBIOS";
            btnSave.Location = new Point(414, 598);
            btnSave.Size = new Size(730, 42);
            btnSave.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            btnSave.BackColor = Color.FromArgb(37, 99, 235);
            btnSave.ForeColor = Color.White;
            btnSave.FlatStyle = FlatStyle.Flat;
            btnSave.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
            btnSave.Click += BtnSaveTxt_Click;
            page.Controls.Add(btnSave);
        }

        private void BuildTabExcel(TabPage page)
        {
            GroupBox grpTop = new GroupBox();
            grpTop.Text = "Configuraci\u00F3n de Sede, Organizaci\u00F3n y T\u00E9cnicos Responsables";
            grpTop.Location = new Point(14, 10);
            grpTop.Size = new Size(1132, 94);
            grpTop.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            grpTop.BackColor = Color.White;
            page.Controls.Add(grpTop);

            AddLabel(grpTop, "Instituci\u00F3n:", 12, 26, 78);
            cmbInst = new ComboBox();
            cmbInst.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbInst.Items.AddRange(new object[] {
                "Autom\u00E1tico por Hostname (C = IDAC / W = Wiener)",
                "Instituto Carri\u00F3n (IDAC)",
                "Universidad Norbert Wiener"
            });
            cmbInst.SelectedIndex = 0;
            cmbInst.Location = new Point(92, 23);
            cmbInst.Size = new Size(300, 24);
            cmbInst.SelectedIndexChanged += delegate { LoadTxtFilesIntoTable(); };
            grpTop.Controls.Add(cmbInst);

            AddLabel(grpTop, "Sigla Wiener:", 402, 26, 92);
            txtOrgW = new TextBox();
            txtOrgW.Text = orgWienerGuardada;
            txtOrgW.Location = new Point(496, 23);
            txtOrgW.Size = new Size(72, 24);
            grpTop.Controls.Add(txtOrgW);

            AddLabel(grpTop, "Filtrar Vista:", 578, 26, 82);
            cmbFiltro = new ComboBox();
            cmbFiltro.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbFiltro.Items.AddRange(new object[] { "TODOS", "ADMINISTRATIVOS", "AULAS", "LABORATORIO" });
            cmbFiltro.SelectedIndex = 0;
            cmbFiltro.Location = new Point(662, 23);
            cmbFiltro.Size = new Size(165, 24);
            cmbFiltro.SelectedIndexChanged += delegate { ApplyGridFilter(); };
            grpTop.Controls.Add(cmbFiltro);

            Button btnReload = new Button();
            btnReload.Text = "Recargar .txt";
            btnReload.Location = new Point(840, 21);
            btnReload.Size = new Size(132, 28);
            btnReload.BackColor = Color.FromArgb(224, 242, 254);
            btnReload.FlatStyle = FlatStyle.Flat;
            btnReload.Click += delegate { LoadTxtFilesIntoTable(); };
            grpTop.Controls.Add(btnReload);

            Button btnSaveGrid = new Button();
            btnSaveGrid.Text = "Guardar en .txt";
            btnSaveGrid.Location = new Point(980, 21);
            btnSaveGrid.Size = new Size(135, 28);
            btnSaveGrid.BackColor = Color.FromArgb(220, 252, 231);
            btnSaveGrid.FlatStyle = FlatStyle.Flat;
            btnSaveGrid.Click += BtnSaveGrid_Click;
            grpTop.Controls.Add(btnSaveGrid);

            AddLabel(grpTop, "T\u00E9cnicos:", 12, 60, 78);
            txtTec = new TextBox();
            txtTec.Text = tecnicosResponsables;
            txtTec.Location = new Point(92, 57);
            txtTec.Size = new Size(525, 24);
            grpTop.Controls.Add(txtTec);

            Button btnAsistTec = new Button();
            btnAsistTec.Text = "Asistente T\u00E9cnicos en Sede";
            btnAsistTec.Location = new Point(625, 55);
            btnAsistTec.Size = new Size(202, 28);
            btnAsistTec.BackColor = Color.FromArgb(254, 243, 199);
            btnAsistTec.FlatStyle = FlatStyle.Flat;
            btnAsistTec.Click += BtnAsistTec_Click;
            grpTop.Controls.Add(btnAsistTec);

            Button btnAddRow = new Button();
            btnAddRow.Text = "+ Fila Manual";
            btnAddRow.Location = new Point(840, 55);
            btnAddRow.Size = new Size(132, 28);
            btnAddRow.BackColor = Color.FromArgb(220, 252, 231);
            btnAddRow.FlatStyle = FlatStyle.Flat;
            btnAddRow.Click += BtnAddRow_Click;
            grpTop.Controls.Add(btnAddRow);

            Button btnDelRow = new Button();
            btnDelRow.Text = "Eliminar Fila";
            btnDelRow.Location = new Point(980, 55);
            btnDelRow.Size = new Size(135, 28);
            btnDelRow.BackColor = Color.FromArgb(254, 226, 226);
            btnDelRow.FlatStyle = FlatStyle.Flat;
            btnDelRow.Click += BtnDelRow_Click;
            grpTop.Controls.Add(btnDelRow);

            grid = new DataGridView();
            grid.Location = new Point(14, 110);
            grid.Size = new Size(1132, 478);
            grid.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            grid.ReadOnly = false;
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = true;
            grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCells;
            grid.BackgroundColor = Color.White;
            grid.BorderStyle = BorderStyle.FixedSingle;
            grid.RowHeadersWidth = 28;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(30, 41, 59);
            grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            grid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 9F);
            grid.EnableHeadersVisualStyles = false;
            grid.CellFormatting += Grid_CellFormatting;
            page.Controls.Add(grid);

            Button btnExportXlsx = new Button();
            btnExportXlsx.Text = "EXPORTAR EXCEL (.XLSX)";
            btnExportXlsx.Location = new Point(14, 598);
            btnExportXlsx.Size = new Size(230, 44);
            btnExportXlsx.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnExportXlsx.BackColor = Color.FromArgb(21, 128, 61);
            btnExportXlsx.ForeColor = Color.White;
            btnExportXlsx.FlatStyle = FlatStyle.Flat;
            btnExportXlsx.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
            btnExportXlsx.Click += BtnExportXlsx_Click;
            page.Controls.Add(btnExportXlsx);

            Button btnCopyAdm = new Button();
            btnCopyAdm.Text = "Copiar ADMINISTRATIVOS";
            btnCopyAdm.Location = new Point(254, 598);
            btnCopyAdm.Size = new Size(215, 44);
            btnCopyAdm.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnCopyAdm.BackColor = Color.FromArgb(37, 99, 235);
            btnCopyAdm.ForeColor = Color.White;
            btnCopyAdm.FlatStyle = FlatStyle.Flat;
            btnCopyAdm.Click += delegate { CopyFilteredRowsToClipboard("ADMINISTRATIVOS"); };
            page.Controls.Add(btnCopyAdm);

            Button btnCopyAu = new Button();
            btnCopyAu.Text = "Copiar AULAS";
            btnCopyAu.Location = new Point(479, 598);
            btnCopyAu.Size = new Size(195, 44);
            btnCopyAu.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnCopyAu.BackColor = Color.FromArgb(37, 99, 235);
            btnCopyAu.ForeColor = Color.White;
            btnCopyAu.FlatStyle = FlatStyle.Flat;
            btnCopyAu.Click += delegate { CopyFilteredRowsToClipboard("AULAS"); };
            page.Controls.Add(btnCopyAu);

            Button btnCopyLab = new Button();
            btnCopyLab.Text = "Copiar LABORATORIO";
            btnCopyLab.Location = new Point(684, 598);
            btnCopyLab.Size = new Size(210, 44);
            btnCopyLab.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnCopyLab.BackColor = Color.FromArgb(37, 99, 235);
            btnCopyLab.ForeColor = Color.White;
            btnCopyLab.FlatStyle = FlatStyle.Flat;
            btnCopyLab.Click += delegate { CopyFilteredRowsToClipboard("LABORATORIO"); };
            page.Controls.Add(btnCopyLab);

            Button btnCopyAll = new Button();
            btnCopyAll.Text = "Copiar Vista Actual (Ctrl+V)";
            btnCopyAll.Location = new Point(904, 598);
            btnCopyAll.Size = new Size(242, 44);
            btnCopyAll.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnCopyAll.BackColor = Color.FromArgb(109, 40, 217);
            btnCopyAll.ForeColor = Color.White;
            btnCopyAll.FlatStyle = FlatStyle.Flat;
            btnCopyAll.Click += delegate { CopyFilteredRowsToClipboard("VISTA_ACTUAL"); };
            page.Controls.Add(btnCopyAll);
        }

        private void AddLabel(Control parent, string text, int x, int y, int width)
        {
            Label l = new Label();
            l.Text = text;
            l.Location = new Point(x, y);
            l.Size = new Size(width, 20);
            parent.Controls.Add(l);
        }

        private TextBox AddEditableRow(Control parent, string labelText, int y, int height, bool multiline)
        {
            AddLabel(parent, labelText, 12, y + 3, 120);
            TextBox t = new TextBox();
            t.Location = new Point(135, y);
            t.Size = new Size(405, height);
            if (multiline)
            {
                t.Multiline = true;
                t.ScrollBars = ScrollBars.Vertical;
            }
            t.TextChanged += delegate {
                if (t.Text.IndexOf("validar presencialmente", StringComparison.OrdinalIgnoreCase) >= 0)
                    t.BackColor = Color.FromArgb(254, 249, 195);
                else
                    t.BackColor = Color.White;
                UpdatePreview();
            };
            parent.Controls.Add(t);
            return t;
        }

        private void RefreshAreaCombo()
        {
            string current = cmbArea != null ? cmbArea.Text : "";
            if (cmbArea == null) return;
            cmbArea.Items.Clear();
            List<string> vals = areaMap.Values.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).ToList();
            foreach (string v in vals) cmbArea.Items.Add(v);
            if (!string.IsNullOrEmpty(current)) cmbArea.Text = current;
        }

        private string CleanValue(string val, string fallback, bool isSerial)
        {
            if (string.IsNullOrWhiteSpace(val)) return fallback;
            string v = val.Trim();
            string[] badList = new string[] {
                "Default string", "To be filled by O.E.M.", "System Product Name",
                "System Serial Number", "System manufacturer", "System Version",
                "None", "Not Specified", "Not Applicable", "N/A", "NA",
                "O.E.M.", "0", "1", "123456789", "Serial Number", "Chassis Serial Number"
            };
            foreach (string b in badList)
            {
                if (string.Equals(v, b, StringComparison.OrdinalIgnoreCase))
                    return fallback;
            }
            if (isSerial)
            {
                if (v.Length < 4 || Regex.IsMatch(v, @"^(.)\1+$"))
                    return fallback;
            }
            return v;
        }

        private void ScanCurrentHardware()
        {
            this.Cursor = Cursors.WaitCursor;
            suppressPreview = true;
            currentAjustes = new List<KeyValuePair<string, string>>();
            lblStatusText.Text = "Escaneando hardware, red, monitores y perfiles de usuario...";
            Application.DoEvents();

            try
            {
                string csName = Environment.MachineName;
                string csDomain = "WORKGROUP";
                string csManufacturer = "";
                string csModel = "";
                ulong totalPhysMem = 0;

                using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT Name, Domain, Manufacturer, Model, TotalPhysicalMemory, UserName FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject mo in s.Get())
                    {
                        if (mo["Name"] != null) csName = mo["Name"].ToString().Trim();
                        if (mo["Domain"] != null) csDomain = mo["Domain"].ToString().Trim();
                        if (mo["Manufacturer"] != null) csManufacturer = mo["Manufacturer"].ToString().Trim();
                        if (mo["Model"] != null) csModel = mo["Model"].ToString().Trim();
                        if (mo["TotalPhysicalMemory"] != null) ulong.TryParse(mo["TotalPhysicalMemory"].ToString(), out totalPhysMem);
                        if (mo["UserName"] != null) currentUserExec = mo["UserName"].ToString().Trim();
                        break;
                    }
                }
                if (string.IsNullOrEmpty(currentUserExec))
                    currentUserExec = Environment.UserDomainName + "\\" + Environment.UserName;

                string tipoEquipo = "No identificado (validar presencialmente)";
                Dictionary<int, string> chassisDict = new Dictionary<int, string>() {
                    {3,"Desktop / Torre"}, {4,"Desktop Low Profile"}, {5,"Desktop Slim"}, {6,"Mini Torre"}, {7,"Torre"},
                    {8,"Laptop / Portatil"}, {9,"Laptop"}, {10,"Notebook"}, {11,"Handheld"}, {13,"All-in-One (Todo en Uno)"},
                    {14,"Sub-Notebook"}, {15,"Desktop Compacto"}, {17,"Servidor"}, {23,"Servidor Rack"},
                    {30,"Tablet"}, {31,"Convertible 2-en-1"}, {32,"Laptop Desmontable"}, {35,"Mini PC"}, {36,"Mini PC Stick"}
                };
                try
                {
                    using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT ChassisTypes FROM Win32_SystemEnclosure"))
                    {
                        foreach (ManagementObject mo in s.Get())
                        {
                            ushort[] types = mo["ChassisTypes"] as ushort[];
                            if (types != null && types.Length > 0 && chassisDict.ContainsKey((int)types[0]))
                            {
                                tipoEquipo = chassisDict[(int)types[0]];
                                break;
                            }
                        }
                    }
                }
                catch { }

                string cspVersion = "";
                try
                {
                    using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT Version FROM Win32_ComputerSystemProduct"))
                    {
                        foreach (ManagementObject mo in s.Get())
                        {
                            if (mo["Version"] != null) cspVersion = mo["Version"].ToString().Trim();
                            break;
                        }
                    }
                }
                catch { }

                string marca = CleanValue(csManufacturer, "No se pudo obtener la marca del equipo (validar presencialmente)", false);
                string modClean = CleanValue(csModel, "", false);
                string verClean = CleanValue(cspVersion, "", false);
                string modelo;
                if (!string.IsNullOrEmpty(modClean) && !string.IsNullOrEmpty(verClean) && !string.Equals(modClean, verClean, StringComparison.OrdinalIgnoreCase))
                    modelo = string.Format("{0} ({1})", modClean, verClean);
                else if (!string.IsNullOrEmpty(modClean))
                    modelo = modClean;
                else if (!string.IsNullOrEmpty(verClean))
                    modelo = verClean;
                else
                    modelo = "No se pudo obtener el modelo del equipo (validar presencialmente)";

                string biosSerial = "";
                try
                {
                    using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS"))
                    {
                        foreach (ManagementObject mo in s.Get())
                        {
                            if (mo["SerialNumber"] != null) biosSerial = mo["SerialNumber"].ToString().Trim();
                            break;
                        }
                    }
                }
                catch { }

                string serieEquipo = CleanValue(biosSerial, "", true);
                if (string.IsNullOrEmpty(serieEquipo))
                {
                    string boardSerial = "";
                    try
                    {
                        using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard"))
                        {
                            foreach (ManagementObject mo in s.Get())
                            {
                                if (mo["SerialNumber"] != null) boardSerial = mo["SerialNumber"].ToString().Trim();
                                break;
                            }
                        }
                    }
                    catch { }
                    string bClean = CleanValue(boardSerial, "", true);
                    serieEquipo = !string.IsNullOrEmpty(bClean)
                        ? bClean + " (Serie Placa Base)"
                        : "No se pudo obtener la serie del equipo (validar presencialmente)";
                }

                string osCaption = "";
                string osBuild = "";
                try
                {
                    using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT Caption, BuildNumber FROM Win32_OperatingSystem"))
                    {
                        foreach (ManagementObject mo in s.Get())
                        {
                            if (mo["Caption"] != null) osCaption = mo["Caption"].ToString().Replace("Microsoft ", "").Trim();
                            if (mo["BuildNumber"] != null) osBuild = mo["BuildNumber"].ToString().Trim();
                            break;
                        }
                    }
                }
                catch { }

                string dispVer = "";
                try
                {
                    using (RegistryKey rk = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                    {
                        if (rk != null)
                        {
                            object dv = rk.GetValue("DisplayVersion") ?? rk.GetValue("ReleaseId");
                            if (dv != null) dispVer = dv.ToString();
                        }
                    }
                }
                catch { }
                string sistemaOp = !string.IsNullOrEmpty(dispVer)
                    ? string.Format("{0} ({1} - Build {2})", osCaption, dispVer, osBuild)
                    : string.Format("{0} (Build {1})", osCaption, osBuild);

                string cpuRaw = "";
                try
                {
                    using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT Name FROM Win32_Processor"))
                    {
                        foreach (ManagementObject mo in s.Get())
                        {
                            if (mo["Name"] != null) cpuRaw = mo["Name"].ToString().Trim();
                            break;
                        }
                    }
                }
                catch { }
                string cpu = CleanValue(cpuRaw, "No se pudo obtener el procesador (validar presencialmente)", false);

                string ram = "";
                try
                {
                    Dictionary<int, string> memTypeMap = new Dictionary<int, string>() {
                        {20,"DDR"}, {21,"DDR2"}, {24,"DDR3"}, {26,"DDR4"}, {34,"DDR5"}
                    };
                    List<string> stickDescs = new List<string>();
                    ulong sumBytes = 0;
                    using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT Capacity, SMBIOSMemoryType, ConfiguredClockSpeed, Speed FROM Win32_PhysicalMemory"))
                    {
                        foreach (ManagementObject mo in s.Get())
                        {
                            ulong cap = 0;
                            if (mo["Capacity"] != null) ulong.TryParse(mo["Capacity"].ToString(), out cap);
                            sumBytes += cap;
                            int gbStick = (int)Math.Round(cap / (1024.0 * 1024.0 * 1024.0));
                            int mCode = 0;
                            if (mo["SMBIOSMemoryType"] != null) int.TryParse(mo["SMBIOSMemoryType"].ToString(), out mCode);
                            string mType = memTypeMap.ContainsKey(mCode) ? memTypeMap[mCode] : "RAM";
                            string spd = "";
                            if (mo["ConfiguredClockSpeed"] != null) spd = " @ " + mo["ConfiguredClockSpeed"].ToString() + " MHz";
                            else if (mo["Speed"] != null) spd = " @ " + mo["Speed"].ToString() + " MHz";
                            stickDescs.Add(string.Format("{0} GB {1}{2}", gbStick, mType, spd));
                        }
                    }
                    if (stickDescs.Count > 0)
                    {
                        int totalGb = (int)Math.Round(sumBytes / (1024.0 * 1024.0 * 1024.0));
                        var groups = stickDescs.GroupBy(x => x).Select(g => string.Format("{0}x {1}", g.Count(), g.Key));
                        ram = string.Format("{0} GB ({1})", totalGb, string.Join(" + ", groups.ToArray()));
                    }
                }
                catch { }
                if (string.IsNullOrEmpty(ram))
                {
                    if (totalPhysMem > 0)
                        ram = Math.Round(totalPhysMem / (1024.0 * 1024.0 * 1024.0)).ToString() + " GB";
                    else
                        ram = "No se pudo obtener la RAM (validar presencialmente)";
                }

                List<string> diskItems = new List<string>();
                try
                {
                    Dictionary<ushort, string> busMap = new Dictionary<ushort, string>() {
                        {3,"ATA"}, {7,"USB"}, {8,"RAID"}, {11,"SATA"}, {17,"NVMe"}
                    };
                    Dictionary<ushort, string> mediaMap = new Dictionary<ushort, string>() {
                        {3,"HDD"}, {4,"SSD"}
                    };
                    ManagementScope scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Storage");
                    scope.Connect();
                    using (ManagementObjectSearcher s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT FriendlyName, Size, BusType, MediaType FROM MSFT_PhysicalDisk")))
                    {
                        foreach (ManagementObject mo in s.Get())
                        {
                            ushort bus = 0;
                            if (mo["BusType"] != null) ushort.TryParse(mo["BusType"].ToString(), out bus);
                            if (bus == 7) continue;

                            string dMod = CleanValue(mo["FriendlyName"] != null ? mo["FriendlyName"].ToString() : "", "Disco sin modelo", false);
                            ulong sz = 0;
                            if (mo["Size"] != null) ulong.TryParse(mo["Size"].ToString(), out sz);
                            int dGb = (int)Math.Round(sz / (1024.0 * 1024.0 * 1024.0));

                            ushort med = 0;
                            if (mo["MediaType"] != null) ushort.TryParse(mo["MediaType"].ToString(), out med);
                            string bStr = busMap.ContainsKey(bus) ? busMap[bus] : "";
                            string mStr = mediaMap.ContainsKey(med) ? mediaMap[med] : "";
                            string tag = (bStr + " " + mStr).Trim();

                            if (!string.IsNullOrEmpty(tag))
                                diskItems.Add(string.Format("{0} [{1}] ({2} GB)", dMod, tag, dGb));
                            else
                                diskItems.Add(string.Format("{0} ({1} GB)", dMod, dGb));
                        }
                    }
                }
                catch { }

                if (diskItems.Count == 0)
                {
                    try
                    {
                        using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT Model, Size, InterfaceType FROM Win32_DiskDrive"))
                        {
                            foreach (ManagementObject mo in s.Get())
                            {
                                string iface = mo["InterfaceType"] != null ? mo["InterfaceType"].ToString() : "";
                                if (string.Equals(iface, "USB", StringComparison.OrdinalIgnoreCase)) continue;
                                string dMod = CleanValue(mo["Model"] != null ? mo["Model"].ToString() : "", "Disco sin modelo", false);
                                ulong sz = 0;
                                if (mo["Size"] != null) ulong.TryParse(mo["Size"].ToString(), out sz);
                                int dGb = (int)Math.Round(sz / (1024.0 * 1024.0 * 1024.0));
                                diskItems.Add(string.Format("{0} ({1} GB)", dMod, dGb));
                            }
                        }
                    }
                    catch { }
                }
                string almacenamiento = diskItems.Count > 0
                    ? string.Join(" / ", diskItems.ToArray())
                    : "No se pudo obtener el almacenamiento (validar presencialmente)";

                List<string> userLines = ScanUserProfiles(csName);
                activeNets = ScanActiveNetworks();
                List<string> monLines = ScanMonitorsEdid();
                lblStatusText.Text = "Detectando antivirus, Absolute y HP Insights...";
                Application.DoEvents();
                ScanSecuritySoftware(out secAntivirus, out secAbsolute, out secHpInsights);

                string hostUpper = csName.ToUpper();
                string tipoFinal = NormalizeTipoEquipo(tipoEquipo, hostUpper);
                bool esLaptop = tipoFinal == "LAPTOP";

                Match mAu = Regex.Match(hostUpper, @"^[A-Z]+\d+(?:PC|LP)AU(\d{3})(\d*)$");
                Match mLb = Regex.Match(hostUpper, @"^[A-Z]+\d+(?:PC|LP)LB(\d{3})(\d*)$");
                Match mAd = Regex.Match(hostUpper, @"^[A-Z]+\d+(?:PC|LP)AD([A-Z]+)(\d*)$");

                if (mAu.Success)
                {
                    string numAula = mAu.Groups[1].Value;
                    cmbCat.Text = "AULAS";
                    cmbArea.Text = "AULA " + numAula;
                    txtPiso.Text = numAula.Substring(0, 1);
                    cmbSeg.Text = esLaptop ? "CADENA DE SEGURIDAD" : "SIN REMACHE/SIN CADENA";
                }
                else if (mLb.Success)
                {
                    string numLab = mLb.Groups[1].Value;
                    cmbCat.Text = "LABORATORIO";
                    cmbArea.Text = "LABORATORIO DE COMPUTO " + numLab;
                    txtPiso.Text = numLab.Substring(0, 1);
                    cmbSeg.Text = esLaptop ? "CADENA DE SEGURIDAD" : "CON REMACHE/SIN CADENA";
                }
                else if (mAd.Success)
                {
                    string codArea = mAd.Groups[1].Value.ToUpper();
                    cmbCat.Text = "ADMINISTRATIVOS";
                    if (!areaMap.ContainsKey(codArea))
                    {
                        string nuevoNom = PromptInput("Nueva Sigla Detectada",
                            string.Format("El equipo {0} contiene la sigla de \u00E1rea [{1}].\nIngresa el nombre completo del \u00C1REA (ej. ADMISION, CAJA, RRHH):", hostUpper, codArea), "");
                        if (!string.IsNullOrWhiteSpace(nuevoNom))
                        {
                            areaMap[codArea] = nuevoNom.Trim().ToUpper();
                            SaveConfig();
                            RefreshAreaCombo();
                        }
                    }
                    cmbArea.Text = areaMap.ContainsKey(codArea) ? areaMap[codArea] : codArea;
                    txtPiso.Text = pisosMap.ContainsKey(codArea) ? pisosMap[codArea] : "1";
                    cmbSeg.Text = esLaptop ? "CADENA DE SEGURIDAD" : "NINGUNO";
                }
                else
                {
                    cmbCat.Text = "ADMINISTRATIVOS";
                    if (string.IsNullOrWhiteSpace(cmbArea.Text)) cmbArea.Text = "SOPORTE T\u00C9CNICO";
                    if (string.IsNullOrWhiteSpace(txtPiso.Text)) txtPiso.Text = "1";
                    cmbSeg.Text = esLaptop ? "CADENA DE SEGURIDAD" : "SIN REMACHE/SIN CADENA";
                }

                txtTipo.Text   = tipoFinal;
                txtMarca.Text  = marca;
                txtModelo.Text = modelo;
                txtSerie.Text  = serieEquipo;
                txtHost.Text   = csName;
                txtDom.Text    = csDomain;
                txtSO.Text     = sistemaOp;
                txtCPU.Text    = cpu;
                txtRAM.Text    = ram;
                txtDisk.Text   = almacenamiento;
                txtUsers.Text  = string.Join(Environment.NewLine, userLines.ToArray());
                txtMons.Text   = string.Join(Environment.NewLine, monLines.ToArray());

                lblStatusText.Text = "Escaneo nativo completado correctamente para " + csName + ".";
            }
            finally
            {
                suppressPreview = false;
                UpdatePreview();
                this.Cursor = Cursors.Default;
            }
        }

        private List<string> ScanUserProfiles(string machineName)
        {
            List<string> list = new List<string>();
            string[] excluded = new string[] { "defaultuser0", "Guest", "Invitado", "WDAGUtilityAccount", "Administrador", "Administrator" };

            try
            {
                using (RegistryKey profList = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"))
                {
                    if (profList == null) return list;
                    foreach (string sidStr in profList.GetSubKeyNames())
                    {
                        if (!sidStr.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) &&
                            !sidStr.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase))
                            continue;

                        using (RegistryKey pk = profList.OpenSubKey(sidStr))
                        {
                            if (pk == null) continue;
                            string pPath = pk.GetValue("ProfileImagePath") as string;
                            if (string.IsNullOrEmpty(pPath) || Regex.IsMatch(pPath, @"\\TEMP(\.|$)", RegexOptions.IgnoreCase))
                                continue;

                            string cuentaFull = "";
                            try
                            {
                                SecurityIdentifier sid = new SecurityIdentifier(sidStr);
                                cuentaFull = sid.Translate(typeof(NTAccount)).Value;
                            }
                            catch
                            {
                                cuentaFull = Path.GetFileName(pPath.TrimEnd('\\'));
                            }

                            string userOnly = cuentaFull.Contains("\\")
                                ? cuentaFull.Substring(cuentaFull.IndexOf('\\') + 1)
                                : cuentaFull;

                            if (excluded.Any(e => string.Equals(e, userOnly, StringComparison.OrdinalIgnoreCase)))
                                continue;

                            string origen = "Dominio";
                            if (sidStr.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase))
                                origen = "EntraID / Microsoft";
                            else if (cuentaFull.StartsWith(machineName + "\\", StringComparison.OrdinalIgnoreCase))
                                origen = "Local";

                            string nombreCompleto = "";
                            string correoUsuario = "";

                            if (origen == "Dominio")
                            {
                                try
                                {
                                    using (DirectorySearcher ds = new DirectorySearcher())
                                    {
                                        ds.Filter = string.Format("(&(objectCategory=person)(objectClass=user)(sAMAccountName={0}))", userOnly);
                                        ds.PropertiesToLoad.Add("displayName");
                                        ds.PropertiesToLoad.Add("cn");
                                        ds.PropertiesToLoad.Add("mail");
                                        ds.PropertiesToLoad.Add("userPrincipalName");
                                        ds.PageSize = 1;
                                        SearchResult sr = ds.FindOne();
                                        if (sr != null)
                                        {
                                            if (sr.Properties["displayName"] != null && sr.Properties["displayName"].Count > 0)
                                                nombreCompleto = sr.Properties["displayName"][0].ToString();
                                            else if (sr.Properties["cn"] != null && sr.Properties["cn"].Count > 0)
                                                nombreCompleto = sr.Properties["cn"][0].ToString();

                                            if (sr.Properties["mail"] != null && sr.Properties["mail"].Count > 0)
                                                correoUsuario = sr.Properties["mail"][0].ToString();
                                            else if (sr.Properties["userPrincipalName"] != null && sr.Properties["userPrincipalName"].Count > 0)
                                                correoUsuario = sr.Properties["userPrincipalName"][0].ToString();
                                        }
                                    }
                                }
                                catch { }
                            }
                            else if (origen == "Local")
                            {
                                try
                                {
                                    string q = string.Format("SELECT FullName FROM Win32_UserAccount WHERE LocalAccount=True AND Name='{0}'", userOnly.Replace("'", "''"));
                                    using (ManagementObjectSearcher s = new ManagementObjectSearcher(q))
                                    {
                                        foreach (ManagementObject mo in s.Get())
                                        {
                                            if (mo["FullName"] != null) nombreCompleto = mo["FullName"].ToString().Trim();
                                            break;
                                        }
                                    }
                                }
                                catch { }
                            }

                            string nomFin = CleanValue(nombreCompleto, "Sin nombre registrado", false);
                            string corFin = CleanValue(correoUsuario, "Sin correo registrado", false);
                            list.Add(string.Format("Usuario: {0} [{1}] | Nombre: {2} | Correo: {3}", cuentaFull, origen, nomFin, corFin));
                        }
                    }
                }
            }
            catch { }
            return list;
        }

        private List<NetAdapterInfo> ScanActiveNetworks()
        {
            List<NetAdapterInfo> nets = new List<NetAdapterInfo>();
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                        ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

                    IPInterfaceProperties ipProps = ni.GetIPProperties();
                    var gwList = ipProps.GatewayAddresses
                        .Where(g => g.Address != null && g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.ToString().Equals("0.0.0.0"))
                        .Select(g => g.Address.ToString()).ToList();

                    if (gwList.Count == 0) continue;

                    var ipv4List = ipProps.UnicastAddresses
                        .Where(u => u.Address != null && u.Address.AddressFamily == AddressFamily.InterNetwork)
                        .Select(u => u.Address.ToString()).ToList();

                    var dnsList = ipProps.DnsAddresses
                        .Where(d => d.AddressFamily == AddressFamily.InterNetwork)
                        .Select(d => d.ToString()).ToList();

                    byte[] macBytes = ni.GetPhysicalAddress().GetAddressBytes();
                    string macStr = macBytes.Length > 0
                        ? string.Join("-", macBytes.Select(b => b.ToString("X2")).ToArray())
                        : "No disponible (validar presencialmente)";

                    NetAdapterInfo info = new NetAdapterInfo();
                    info.Description = CleanValue(ni.Description, "Adaptador sin descripcion", false);
                    info.IPv4 = ipv4List.Count > 0 ? string.Join(", ", ipv4List.ToArray()) : "No disponible (validar presencialmente)";
                    info.Gateway = string.Join(", ", gwList.ToArray());
                    info.DNS = dnsList.Count > 0 ? string.Join(", ", dnsList.ToArray()) : "No asignado";
                    info.MAC = macStr;
                    nets.Add(info);
                }
            }
            catch { }
            return nets;
        }

        private string DecodeEdidUInt16(object propVal)
        {
            ushort[] arr = propVal as ushort[];
            if (arr == null || arr.Length == 0) return "";
            List<byte> bytes = new List<byte>();
            foreach (ushort u in arr)
            {
                if (u > 0 && u < 256) bytes.Add((byte)u);
            }
            return Encoding.ASCII.GetString(bytes.ToArray()).Trim();
        }

        private List<string> ScanMonitorsEdid()
        {
            List<string> mons = new List<string>();
            try
            {
                ManagementScope scope = new ManagementScope(@"\\.\root\wmi");
                scope.Connect();
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT ManufacturerName, UserFriendlyName, SerialNumberID FROM WmiMonitorID")))
                {
                    foreach (ManagementObject mo in s.Get())
                    {
                        string mfgCode = DecodeEdidUInt16(mo["ManufacturerName"]).ToUpper();
                        string mfg;
                        if (!string.IsNullOrEmpty(mfgCode) && pnpMonitorMap.ContainsKey(mfgCode))
                            mfg = pnpMonitorMap[mfgCode];
                        else if (!string.IsNullOrEmpty(mfgCode))
                            mfg = mfgCode + " (codigo fabricante - validar marca presencialmente)";
                        else
                            mfg = "No se pudo obtener la marca (validar presencialmente)";

                        string nameRaw = DecodeEdidUInt16(mo["UserFriendlyName"]);
                        string name = CleanValue(nameRaw, "No se pudo obtener el modelo (validar presencialmente)", false);

                        string serRaw = DecodeEdidUInt16(mo["SerialNumberID"]);
                        string serial = CleanValue(serRaw, "No se pudo obtener la serie (validar presencialmente)", true);

                        mons.Add(string.Format("Marca: {0} | Modelo: {1} | Serie: {2}", mfg, name, serial));
                    }
                }
            }
            catch { }
            return mons;
        }

        // ===================== Google Drive (equipos con la USB bloqueada) =====================
        // Cada tecnico inicia sesion con SU cuenta de Google en el navegador (OAuth 2.0 para apps de escritorio con
        // PKCE y redireccion a 127.0.0.1). La sesion solo vive en memoria mientras el programa esta abierto: no se
        // guarda ningun token en disco. Los reportes se suben a la carpeta compartida GDRIVE_FOLDER (creada en la cuenta
        // del responsable y compartida como editor con los tecnicos) y, al importarlos a la USB, se mueven a la
        // subcarpeta "Importados". La credencial del proyecto de Google Cloud se inserta al compilar
        // (build\preparar_fuente.ps1 + build\google_oauth.local.json); en el repositorio quedan los marcadores.

        private const string GOOGLE_CLIENT_ID = "__GOOGLE_CLIENT_ID__";
        private const string GOOGLE_CLIENT_SECRET = "__GOOGLE_CLIENT_SECRET__";
        private const string GDRIVE_SCOPE = "https://www.googleapis.com/auth/drive";
        private const string GDRIVE_FOLDER = "Inventario TI - Reportes";
        private const string GDRIVE_IMPORTED = "Importados";
        private const string GDRIVE_API = "https://www.googleapis.com/drive/v3/";
        private const string FOLDER_MIME = "application/vnd.google-apps.folder";

        private string gAccessToken = null;
        private DateTime gTokenExpiryUtc = DateTime.MinValue;
        private string gUserEmail = "";
        private bool preguntarSubirDrive = true;

        private static bool GoogleConfigured()
        {
            return GOOGLE_CLIENT_ID.IndexOf(".apps.googleusercontent.com", StringComparison.OrdinalIgnoreCase) > 0;
        }

        private bool EnsureGoogleConfigured()
        {
            if (GoogleConfigured()) return true;
            MessageBox.Show("Esta copia del programa no tiene configurada la conexi\u00F3n con Google Drive.\n\n" +
                "Usa el programa del release (InventarioTI_v*.zip) o, si eres el responsable, revisa docs\\GOOGLE_DRIVE.md.",
                "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return false;
        }

        private static string Base64Url(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static string RandomUrlSafe(int bytes)
        {
            byte[] b = new byte[bytes];
            using (System.Security.Cryptography.RandomNumberGenerator rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                rng.GetBytes(b);
            return Base64Url(b);
        }

        private static string PkceChallenge(string verifier)
        {
            using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
                return Base64Url(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier)));
        }

        // "/?state=abc&code=4%2F0A..." -> diccionario
        private static Dictionary<string, string> ParseQueryString(string pathAndQuery)
        {
            Dictionary<string, string> res = new Dictionary<string, string>(StringComparer.Ordinal);
            int q = (pathAndQuery ?? "").IndexOf('?');
            if (q < 0) return res;
            foreach (string part in pathAndQuery.Substring(q + 1).Split('&'))
            {
                if (part.Length == 0) continue;
                int eq = part.IndexOf('=');
                string k = Uri.UnescapeDataString((eq < 0 ? part : part.Substring(0, eq)).Replace('+', ' '));
                string v = eq < 0 ? "" : Uri.UnescapeDataString(part.Substring(eq + 1).Replace('+', ' '));
                res[k] = v;
            }
            return res;
        }

        private static void WriteHttpResponse(Stream s, int status, string html)
        {
            byte[] body = Encoding.UTF8.GetBytes(html ?? "");
            string head = string.Format("HTTP/1.1 {0} {1}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {2}\r\nConnection: close\r\n\r\n",
                status, status == 200 ? "OK" : "Not Found", body.Length);
            byte[] h = Encoding.ASCII.GetBytes(head);
            s.Write(h, 0, h.Length);
            s.Write(body, 0, body.Length);
            s.Flush();
        }

        private static string LoopbackPage(bool ok)
        {
            return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Inventario TI</title></head>" +
                "<body style=\"font-family:Segoe UI,Arial,sans-serif;background:#f1f5f9;color:#0f172a;padding:48px\">" +
                (ok ? "<h2>Sesi\u00F3n iniciada</h2><p>Ya puedes cerrar esta pesta\u00F1a y volver al programa Inventario TI.</p>"
                    : "<h2>No se pudo iniciar sesi\u00F3n</h2><p>Vuelve al programa Inventario TI e int\u00E9ntalo de nuevo.</p>") +
                "</body></html>";
        }

        // Atiende UNA redireccion de Google en el listener. Devuelve el "code" o null (y el error).
        // Las peticiones que no traen code/error (ej. /favicon.ico) se responden con 404 y se sigue esperando.
        private static string WaitForOAuthRedirect(TcpListener listener, string expectedState, out string error)
        {
            error = null;
            while (true)
            {
                using (TcpClient client = listener.AcceptTcpClient())
                {
                    NetworkStream ns = client.GetStream();
                    ns.ReadTimeout = 10000;
                    StreamReader sr = new StreamReader(ns, Encoding.ASCII);
                    string requestLine = sr.ReadLine() ?? "";
                    Match m = Regex.Match(requestLine, @"^GET\s+(\S+)");
                    Dictionary<string, string> q = ParseQueryString(m.Success ? m.Groups[1].Value : "");
                    if (!q.ContainsKey("code") && !q.ContainsKey("error"))
                    {
                        WriteHttpResponse(ns, 404, "");
                        continue;
                    }
                    string st;
                    bool stateOk = q.TryGetValue("state", out st) && st == expectedState;
                    bool ok = stateOk && q.ContainsKey("code");
                    WriteHttpResponse(ns, 200, LoopbackPage(ok));
                    if (ok) return q["code"];
                    error = q.ContainsKey("error") ? q["error"] : "respuesta no v\u00E1lida (state)";
                    return null;
                }
            }
        }

        // Peticion a la API de Google; devuelve el JSON como diccionario. Los errores incluyen el mensaje de Google.
        private static Dictionary<string, object> GoogleRequest(string method, string url, string token, string contentType, byte[] body)
        {
            EnableTls12();
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = method;
            req.UserAgent = UPDATE_UA;
            req.Timeout = 30000;
            req.ReadWriteTimeout = 30000;
            if (token != null) req.Headers[HttpRequestHeader.Authorization] = "Bearer " + token;
            if (body != null)
            {
                req.ContentType = contentType;
                req.ContentLength = body.Length;
                using (Stream s = req.GetRequestStream()) s.Write(body, 0, body.Length);
            }
            try
            {
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                using (StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                {
                    string txt = sr.ReadToEnd();
                    if (txt.Trim().Length == 0) return new Dictionary<string, object>();
                    JavaScriptSerializer ser = new JavaScriptSerializer();
                    ser.MaxJsonLength = int.MaxValue;
                    return ser.Deserialize<Dictionary<string, object>>(txt);
                }
            }
            catch (WebException wex)
            {
                throw new Exception(GoogleErrorMessage(wex));
            }
        }

        private static byte[] GoogleDownload(string url, string token)
        {
            EnableTls12();
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.UserAgent = UPDATE_UA;
            req.Timeout = 30000;
            req.Headers[HttpRequestHeader.Authorization] = "Bearer " + token;
            try
            {
                using (WebResponse resp = req.GetResponse())
                using (Stream s = resp.GetResponseStream())
                using (MemoryStream ms = new MemoryStream())
                {
                    s.CopyTo(ms);
                    return ms.ToArray();
                }
            }
            catch (WebException wex)
            {
                throw new Exception(GoogleErrorMessage(wex));
            }
        }

        private static string GoogleErrorMessage(WebException wex)
        {
            string msg = wex.Message;
            try
            {
                if (wex.Response != null)
                {
                    using (StreamReader sr = new StreamReader(wex.Response.GetResponseStream(), Encoding.UTF8))
                    {
                        string txt = sr.ReadToEnd();
                        Dictionary<string, object> d = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(txt);
                        if (d != null && d.ContainsKey("error"))
                        {
                            Dictionary<string, object> e = d["error"] as Dictionary<string, object>;
                            if (e != null && e.ContainsKey("message")) msg = Convert.ToString(e["message"]);
                            else
                            {
                                msg = Convert.ToString(d["error"]);
                                if (d.ContainsKey("error_description")) msg += ": " + Convert.ToString(d["error_description"]);
                            }
                        }
                    }
                }
            }
            catch { }
            return msg;
        }

        private static string FormEncode(Dictionary<string, string> data)
        {
            List<string> parts = new List<string>();
            foreach (KeyValuePair<string, string> kv in data)
                parts.Add(Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(kv.Value ?? ""));
            return string.Join("&", parts.ToArray());
        }

        // Inicio de sesion en el navegador. Devuelve el access token o null si se cancelo / fallo.
        private string GetGoogleAccessToken()
        {
            if (!EnsureGoogleConfigured()) return null;
            if (gAccessToken != null && DateTime.UtcNow < gTokenExpiryUtc.AddMinutes(-2)) return gAccessToken;

            string verifier = RandomUrlSafe(48);
            string state = RandomUrlSafe(18);
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            string redirect = "http://127.0.0.1:" + port;
            string authUrl = "https://accounts.google.com/o/oauth2/v2/auth?" + FormEncode(new Dictionary<string, string> {
                { "client_id", GOOGLE_CLIENT_ID }, { "redirect_uri", redirect }, { "response_type", "code" },
                { "scope", GDRIVE_SCOPE }, { "code_challenge", PkceChallenge(verifier) }, { "code_challenge_method", "S256" },
                { "state", state }, { "prompt", "select_account" } });

            string code = null;
            string error = null;
            bool terminado = false;
            Thread th = new Thread(delegate()
            {
                try { code = WaitForOAuthRedirect(listener, state, out error); }
                catch { if (error == null) error = "cancelado"; }
                terminado = true;
            });
            th.IsBackground = true;
            th.Start();

            using (Form dlg = new Form())
            {
                dlg.Text = "Iniciar sesi\u00F3n con Google";
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.ControlBox = false;
                dlg.ShowInTaskbar = false;
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.ClientSize = new Size(460, 150);
                dlg.Font = new Font("Segoe UI", 9.5F);
                Label lbl = new Label();
                lbl.Text = "Se abri\u00F3 el navegador. Elige tu cuenta de Google y acepta los permisos.\n" +
                    "Si Google muestra \"Google no verific\u00F3 esta app\", usa Avanzado > Ir a Inventario TI.\n\n" +
                    "Esta ventana se cerrar\u00E1 sola al terminar.";
                lbl.Location = new Point(16, 14);
                lbl.Size = new Size(430, 84);
                Button bCancel = new Button();
                bCancel.Text = "Cancelar";
                bCancel.Size = new Size(100, 30);
                bCancel.Location = new Point(344, 106);
                bCancel.Click += delegate { error = "cancelado"; try { listener.Stop(); } catch { } };
                System.Windows.Forms.Timer poll = new System.Windows.Forms.Timer();
                poll.Interval = 300;
                DateTime limite = DateTime.Now.AddMinutes(5);
                poll.Tick += delegate
                {
                    if (DateTime.Now > limite && !terminado) { error = "tiempo de espera agotado"; try { listener.Stop(); } catch { } }
                    if (terminado) { poll.Stop(); dlg.Close(); }
                };
                dlg.Controls.AddRange(new Control[] { lbl, bCancel });
                dlg.Shown += delegate
                {
                    try { Process.Start(authUrl); }
                    catch (Exception ex) { error = "no se pudo abrir el navegador: " + ex.Message; try { listener.Stop(); } catch { } }
                    poll.Start();
                };
                dlg.ShowDialog(this);
                poll.Dispose();
            }
            try { listener.Stop(); } catch { }
            this.Activate();

            if (code == null)
            {
                if (error != "cancelado")
                    MessageBox.Show("No se pudo iniciar sesi\u00F3n con Google: " + error, "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return null;
            }

            try
            {
                Dictionary<string, object> tok = GoogleRequest("POST", "https://oauth2.googleapis.com/token", null,
                    "application/x-www-form-urlencoded", Encoding.ASCII.GetBytes(FormEncode(new Dictionary<string, string> {
                        { "code", code }, { "client_id", GOOGLE_CLIENT_ID }, { "client_secret", GOOGLE_CLIENT_SECRET },
                        { "redirect_uri", redirect }, { "grant_type", "authorization_code" }, { "code_verifier", verifier } })));
                gAccessToken = Convert.ToString(tok["access_token"]);
                int secs = 3600;
                if (tok.ContainsKey("expires_in")) int.TryParse(Convert.ToString(tok["expires_in"]), out secs);
                gTokenExpiryUtc = DateTime.UtcNow.AddSeconds(secs);
                gUserEmail = "";
                try
                {
                    Dictionary<string, object> about = GoogleRequest("GET", GDRIVE_API + "about?fields=user(emailAddress)", gAccessToken, null, null);
                    Dictionary<string, object> u = about["user"] as Dictionary<string, object>;
                    if (u != null) gUserEmail = Convert.ToString(u["emailAddress"]);
                }
                catch { }
                return gAccessToken;
            }
            catch (Exception ex)
            {
                gAccessToken = null;
                MessageBox.Show("Google rechaz\u00F3 el inicio de sesi\u00F3n: " + ex.Message, "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return null;
            }
        }

        private static string DriveQ(string s)
        {
            return (s ?? "").Replace("\\", "\\\\").Replace("'", "\\'");
        }

        private static List<Dictionary<string, object>> DriveList(string token, string q, string fields)
        {
            List<Dictionary<string, object>> res = new List<Dictionary<string, object>>();
            string pageToken = null;
            do
            {
                string url = GDRIVE_API + "files?pageSize=1000&q=" + Uri.EscapeDataString(q) +
                    "&fields=" + Uri.EscapeDataString("nextPageToken,files(" + fields + ")") +
                    (pageToken != null ? "&pageToken=" + Uri.EscapeDataString(pageToken) : "");
                Dictionary<string, object> r = GoogleRequest("GET", url, token, null, null);
                System.Collections.IEnumerable files = r.ContainsKey("files") ? r["files"] as System.Collections.IEnumerable : null;
                if (files != null)
                    foreach (object o in files)
                    {
                        Dictionary<string, object> d = o as Dictionary<string, object>;
                        if (d != null) res.Add(d);
                    }
                pageToken = r.ContainsKey("nextPageToken") ? Convert.ToString(r["nextPageToken"]) : null;
            } while (!string.IsNullOrEmpty(pageToken));
            return res;
        }

        // ---------- Estructura en Drive ----------
        // Inventario TI - Reportes (raiz, del responsable)
        //   CARRION / WIENER (institucion)
        //     <SEDE> (compartida como Editor con los tecnicos de esa sede)
        //       Respaldo   = copia exacta de la USB de la sede (txt vigentes, historial, Excel, config)
        //       Pendientes = reportes subidos desde equipos con la USB bloqueada; al importarlos pasan a Importados
        // Cada carpeta lleva propiedades (invTI = raiz/inst/sede/respaldo/pendientes, invKey = "CARRION/SJL") para
        // encontrarla aunque el tecnico no vea las carpetas superiores (solo se le comparte su sede).

        private static readonly string[] SEDES_POR_DEFECTO = new string[] {
            "CARRION/SJL", "CARRION/SJM", "CARRION/SARMIENTO", "CARRION/LOS OLIVOS", "CARRION/SAN LUIS", "CARRION/MENDIOLA",
            "WIENER/LOCAL 1", "WIENER/LOCAL 2", "WIENER/LOCAL 4", "WIENER/LOCAL 5", "WIENER/LIMA NORTE"
        };
        private string sedeDrive = "";
        private List<string> driveImportadosIds = new List<string>();

        private class DriveSede
        {
            public string Id;
            public string Key;     // "CARRION/SJL"
            public bool Owned;
        }

        private class RemoteEntry
        {
            public string Id;
            public string Md5;
            public string ParentId;
        }

        private static string PropQ(string key, string value)
        {
            return string.Format("properties has {{ key='{0}' and value='{1}' }}", key, DriveQ(value));
        }

        private static string DriveCreateFolderP(string token, string name, string parentId, Dictionary<string, string> props)
        {
            Dictionary<string, object> meta = new Dictionary<string, object>();
            meta["name"] = name;
            meta["mimeType"] = FOLDER_MIME;
            if (parentId != null) meta["parents"] = new string[] { parentId };
            if (props != null) meta["properties"] = props;
            byte[] body = Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(meta));
            Dictionary<string, object> r = GoogleRequest("POST", GDRIVE_API + "files?fields=id", token, "application/json; charset=UTF-8", body);
            return Convert.ToString(r["id"]);
        }

        private static Dictionary<string, string> Props(string tipo, string key)
        {
            Dictionary<string, string> p = new Dictionary<string, string>();
            p["invTI"] = tipo;
            if (key != null) p["invKey"] = key;
            return p;
        }

        // Sedes a las que esta cuenta tiene acceso (el responsable: todas; un tecnico: las que se le compartieron)
        private static List<DriveSede> ListDriveSedes(string token, bool soloPropias)
        {
            List<DriveSede> res = new List<DriveSede>();
            string q = string.Format("mimeType='{0}' and trashed=false and {1}", FOLDER_MIME, PropQ("invTI", "sede"));
            if (soloPropias) q += " and 'me' in owners";
            foreach (Dictionary<string, object> f in DriveList(token, q, "id,name,ownedByMe,properties"))
            {
                Dictionary<string, object> pr = f.ContainsKey("properties") ? f["properties"] as Dictionary<string, object> : null;
                string key = pr != null && pr.ContainsKey("invKey") ? Convert.ToString(pr["invKey"]) : Convert.ToString(f["name"]);
                DriveSede s = new DriveSede();
                s.Id = Convert.ToString(f["id"]);
                s.Key = key;
                s.Owned = f.ContainsKey("ownedByMe") && f["ownedByMe"] is bool && (bool)f["ownedByMe"];
                if (!res.Any(x => string.Equals(x.Key, key, StringComparison.OrdinalIgnoreCase))) res.Add(s);
            }
            return res.OrderBy(x => x.Key).ToList();
        }

        // Subcarpeta Respaldo / Pendientes de una sede (se crea si falta: los tecnicos son editores de su sede)
        private static string GetSedeSubfolder(string token, DriveSede sede, string tipo, string nombre)
        {
            List<Dictionary<string, object>> f = DriveList(token, string.Format("'{0}' in parents and mimeType='{1}' and trashed=false and {2}",
                DriveQ(sede.Id), FOLDER_MIME, PropQ("invTI", tipo)), "id");
            if (f.Count > 0) return Convert.ToString(f[0]["id"]);
            return DriveCreateFolderP(token, nombre, sede.Id, Props(tipo, sede.Key));
        }

        // Sede de esta USB / equipo. Si no esta configurada (o ya no hay acceso), se elige entre las disponibles.
        private DriveSede ChooseDriveSede(string token, bool forzarEleccion)
        {
            List<DriveSede> sedes = ListDriveSedes(token, false);
            if (sedes.Count == 0)
            {
                MessageBox.Show(string.Format("La cuenta {0} no tiene acceso a ninguna carpeta de sede del inventario en Google Drive.\n\n" +
                    "Si eres t\u00E9cnico, pide al responsable que te agregue a tu sede.\n" +
                    "Si eres el responsable, usa Google Drive > Administrar sedes y t\u00E9cnicos.",
                    gUserEmail.Length > 0 ? gUserEmail : "con la que iniciaste sesi\u00F3n"), "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return null;
            }
            if (!forzarEleccion)
            {
                DriveSede actual = sedes.FirstOrDefault(x => string.Equals(x.Key, sedeDrive, StringComparison.OrdinalIgnoreCase));
                if (actual != null) return actual;
                if (sedes.Count == 1)
                {
                    sedeDrive = sedes[0].Key;
                    SaveConfig();
                    return sedes[0];
                }
            }
            using (Form dlg = new Form())
            {
                dlg.Text = "Sede de esta USB";
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false;
                dlg.MinimizeBox = false;
                dlg.ShowInTaskbar = false;
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.ClientSize = new Size(420, 140);
                dlg.Font = new Font("Segoe UI", 9.5F);
                Label lbl = new Label();
                lbl.Text = "Elige la sede a la que pertenece esta USB (se recordar\u00E1):";
                lbl.Location = new Point(16, 14);
                lbl.AutoSize = true;
                ComboBox cmb = new ComboBox();
                cmb.DropDownStyle = ComboBoxStyle.DropDownList;
                foreach (DriveSede s in sedes) cmb.Items.Add(s.Key.Replace("/", " / "));
                int idx = sedes.FindIndex(x => string.Equals(x.Key, sedeDrive, StringComparison.OrdinalIgnoreCase));
                cmb.SelectedIndex = idx >= 0 ? idx : 0;
                cmb.Location = new Point(18, 42);
                cmb.Size = new Size(384, 26);
                Button bOk = new Button();
                bOk.Text = "Aceptar";
                bOk.DialogResult = DialogResult.OK;
                bOk.Size = new Size(100, 30);
                bOk.Location = new Point(196, 94);
                Button bNo = new Button();
                bNo.Text = "Cancelar";
                bNo.DialogResult = DialogResult.Cancel;
                bNo.Size = new Size(100, 30);
                bNo.Location = new Point(302, 94);
                dlg.AcceptButton = bOk;
                dlg.CancelButton = bNo;
                dlg.Controls.AddRange(new Control[] { lbl, cmb, bOk, bNo });
                if (dlg.ShowDialog(this) != DialogResult.OK) return null;
                sedeDrive = sedes[cmb.SelectedIndex].Key;
                SaveConfig();
                return sedes[cmb.SelectedIndex];
            }
        }

        private void ChangeDriveSede()
        {
            string token = GetGoogleAccessToken();
            if (token == null) return;
            try
            {
                DriveSede s = ChooseDriveSede(token, true);
                if (s != null) lblStatusText.Text = "Sede de Google Drive de esta USB: " + s.Key.Replace("/", " / ");
            }
            catch (Exception ex)
            {
                MessageBox.Show("No se pudo leer Google Drive:\n" + ex.Message, "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static byte[] BuildMultipartRelated(string boundary, string metadataJson, byte[] content, string contentType)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                byte[] a = Encoding.UTF8.GetBytes("--" + boundary + "\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n" + metadataJson +
                    "\r\n--" + boundary + "\r\nContent-Type: " + contentType + "\r\n\r\n");
                byte[] z = Encoding.UTF8.GetBytes("\r\n--" + boundary + "--\r\n");
                ms.Write(a, 0, a.Length);
                ms.Write(content, 0, content.Length);
                ms.Write(z, 0, z.Length);
                return ms.ToArray();
            }
        }

        private static string MimeFor(string name)
        {
            string ext = Path.GetExtension(name ?? "").ToLowerInvariant();
            if (ext == ".xlsx") return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
            if (ext == ".json") return "application/json";
            return "text/plain";
        }

        // Crea (existingId == null) o reemplaza el contenido de un archivo en Drive
        private static string DriveUploadFile(string token, string existingId, string parentId, string name, byte[] content)
        {
            string boundary = "inventario_" + Guid.NewGuid().ToString("N");
            string mime = MimeFor(name);
            string url;
            string method;
            string meta;
            if (existingId != null)
            {
                url = "https://www.googleapis.com/upload/drive/v3/files/" + Uri.EscapeDataString(existingId) + "?uploadType=multipart&fields=id";
                method = "PATCH";
                meta = "{}";
            }
            else
            {
                url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id";
                method = "POST";
                Dictionary<string, object> m = new Dictionary<string, object>();
                m["name"] = name;
                m["mimeType"] = mime;
                m["parents"] = new string[] { parentId };
                meta = new JavaScriptSerializer().Serialize(m);
            }
            Dictionary<string, object> r = GoogleRequest(method, url, token, "multipart/related; boundary=" + boundary,
                BuildMultipartRelated(boundary, meta, content, mime + (mime.StartsWith("text/") ? "; charset=UTF-8" : "")));
            return Convert.ToString(r["id"]);
        }

        // En Drive personal solo el DUENO de un archivo puede mandarlo a la papelera. Si falla (archivo de otro
        // tecnico), se intenta quitarlo de la carpeta. Devuelve null si se pudo, o el motivo.
        private static string DriveRemove(string token, string id, string parentId)
        {
            try
            {
                GoogleRequest("PATCH", GDRIVE_API + "files/" + Uri.EscapeDataString(id) + "?fields=id", token,
                    "application/json; charset=UTF-8", Encoding.UTF8.GetBytes("{\"trashed\":true}"));
                return null;
            }
            catch (Exception ex1)
            {
                try
                {
                    GoogleRequest("PATCH", GDRIVE_API + "files/" + Uri.EscapeDataString(id) + "?removeParents=" + Uri.EscapeDataString(parentId) + "&fields=id",
                        token, "application/json; charset=UTF-8", Encoding.UTF8.GetBytes("{}"));
                    return null;
                }
                catch { return ex1.Message; }
            }
        }

        private static string Md5Hex(string path)
        {
            try
            {
                using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
                using (FileStream fs = File.OpenRead(path))
                {
                    byte[] h = md5.ComputeHash(fs);
                    StringBuilder sb = new StringBuilder();
                    foreach (byte b in h) sb.Append(b.ToString("x2"));
                    return sb.ToString();
                }
            }
            catch { return null; }   // equipos con politica FIPS: se sube siempre
        }

        // ---------- Subir desde un equipo con la USB bloqueada ----------

        private void UploadReportToDrive(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                using (OpenFileDialog dlg = new OpenFileDialog())
                {
                    dlg.Title = "Elige el reporte .txt a subir a Google Drive";
                    dlg.Filter = "Reportes de inventario (*.txt)|*.txt";
                    dlg.InitialDirectory = baseDir;
                    if (dlg.ShowDialog(this) != DialogResult.OK) return;
                    path = dlg.FileName;
                }
            }
            string token = GetGoogleAccessToken();
            if (token == null) return;
            this.Cursor = Cursors.WaitCursor;
            try
            {
                lblStatusText.Text = "Subiendo reporte a Google Drive...";
                Application.DoEvents();
                DriveSede sede = ChooseDriveSede(token, false);
                if (sede == null) return;
                string pendId = GetSedeSubfolder(token, sede, "pendientes", "Pendientes");
                string name = Path.GetFileName(path);
                // Si el mismo equipo ya esta pendiente de importar, se reemplaza (no se duplica)
                List<Dictionary<string, object>> same = DriveList(token,
                    string.Format("name='{0}' and '{1}' in parents and trashed=false", DriveQ(name), DriveQ(pendId)), "id");
                DriveUploadFile(token, same.Count > 0 ? Convert.ToString(same[0]["id"]) : null, pendId, name, File.ReadAllBytes(path));
                lblStatusText.Text = "Reporte subido a Google Drive: " + name;
                MessageBox.Show(string.Format("Reporte subido a Google Drive{0}:\n{1}\n\nSede: {2}  (carpeta Pendientes)\n\n" +
                    "Si este equipo no es tuyo, cierra tu sesi\u00F3n de Google en el navegador.",
                    gUserEmail.Length > 0 ? " (" + gUserEmail + ")" : "", name, sede.Key.Replace("/", " / ")),
                    "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                lblStatusText.Text = "No se pudo subir el reporte a Google Drive.";
                MessageBox.Show("No se pudo subir el reporte a Google Drive:\n" + ex.Message, "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }

        // ---------- Importar los pendientes de la sede a la USB ----------

        private void ImportFromDrive()
        {
            string token = GetGoogleAccessToken();
            if (token == null) return;
            string work = Path.Combine(Path.GetTempPath(), "InventarioTI_drive_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
            Dictionary<string, string> idByLocal = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            DriveSede sede;
            string pendId;
            this.Cursor = Cursors.WaitCursor;
            try
            {
                lblStatusText.Text = "Buscando reportes pendientes en Google Drive...";
                Application.DoEvents();
                sede = ChooseDriveSede(token, false);
                if (sede == null) return;
                pendId = GetSedeSubfolder(token, sede, "pendientes", "Pendientes");
                List<Dictionary<string, object>> files = DriveList(token,
                    string.Format("'{0}' in parents and trashed=false and mimeType!='{1}'", DriveQ(pendId), FOLDER_MIME), "id,name,modifiedTime");
                int n = 0;
                foreach (Dictionary<string, object> f in files)
                {
                    string id = Convert.ToString(f["id"]);
                    string marca = id + "|" + (f.ContainsKey("modifiedTime") ? Convert.ToString(f["modifiedTime"]) : "");
                    if (driveImportadosIds.Contains(marca)) continue;   // ya importado (no se pudo mover por permisos)
                    string name = Regex.Replace(Convert.ToString(f["name"]), @"[\\/:*?""<>|]", "_");
                    if (!name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)) continue;
                    if (n == 0) Directory.CreateDirectory(work);
                    lblStatusText.Text = string.Format("Descargando {0}: {1}", ++n, name);
                    Application.DoEvents();
                    string dir = Path.Combine(work, n.ToString("000"));
                    Directory.CreateDirectory(dir);
                    string local = Path.Combine(dir, name);
                    File.WriteAllBytes(local, GoogleDownload(GDRIVE_API + "files/" + Uri.EscapeDataString(id) + "?alt=media", token));
                    idByLocal[local] = marca;
                }
            }
            catch (Exception ex)
            {
                lblStatusText.Text = "No se pudo leer Google Drive.";
                MessageBox.Show("No se pudieron descargar los reportes de Google Drive:\n" + ex.Message, "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
            if (idByLocal.Count == 0)
            {
                lblStatusText.Text = "No hay reportes pendientes en Google Drive.";
                MessageBox.Show(string.Format("No hay reportes pendientes en la sede {0}.", sede.Key.Replace("/", " / ")), "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            Dictionary<string, string> resultado = ImportReports(new List<string>(idByLocal.Keys));

            // Incorporados (nuevos, actualizados o sin cambios) -> Pendientes/Importados; los omitidos quedan pendientes
            int movidos = 0, incorporados = 0;
            List<string> errores = new List<string>();
            try
            {
                string impId = null;
                foreach (KeyValuePair<string, string> kv in idByLocal)
                {
                    string res;
                    if (!resultado.TryGetValue(kv.Key, out res) || (res != "nuevo" && res != "actualizado" && res != "sin cambios")) continue;
                    if (res != "sin cambios") incorporados++;
                    string fileId = kv.Value.Split('|')[0];
                    if (impId == null)
                    {
                        List<Dictionary<string, object>> sub = DriveList(token,
                            string.Format("mimeType='{0}' and name='{1}' and '{2}' in parents and trashed=false", FOLDER_MIME, GDRIVE_IMPORTED, DriveQ(pendId)), "id");
                        impId = sub.Count > 0 ? Convert.ToString(sub[0]["id"]) : DriveCreateFolderP(token, GDRIVE_IMPORTED, pendId, null);
                    }
                    try
                    {
                        GoogleRequest("PATCH", GDRIVE_API + "files/" + Uri.EscapeDataString(fileId) + "?addParents=" + Uri.EscapeDataString(impId) +
                            "&removeParents=" + Uri.EscapeDataString(pendId) + "&fields=id", token, "application/json; charset=UTF-8", Encoding.UTF8.GetBytes("{}"));
                        movidos++;
                    }
                    catch (Exception ex)
                    {
                        // Sin permiso para moverlo (archivo de otro tecnico): se recuerda para no volver a importarlo
                        if (!driveImportadosIds.Contains(kv.Value)) driveImportadosIds.Add(kv.Value);
                        errores.Add(Path.GetFileName(kv.Key) + ": " + ex.Message);
                    }
                }
                if (errores.Count > 0) SaveConfig();
            }
            catch (Exception ex) { errores.Add(ex.Message); }
            try { Directory.Delete(work, true); } catch { }

            lblStatusText.Text = string.Format("Google Drive: {0} reporte(s) movido(s) a \"{1}\".", movidos, GDRIVE_IMPORTED);
            if (errores.Count > 0)
                MessageBox.Show("Los reportes se incorporaron a la USB, pero algunos no se pudieron mover a \"" + GDRIVE_IMPORTED + "\" en Google Drive " +
                    "(el programa los recordar\u00E1 para no importarlos otra vez):\n\n" + string.Join("\n", errores.Take(10).ToArray()),
                    "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Warning);

            // Lo importado tambien queda en el Respaldo de la sede
            if (incorporados > 0) SyncBackupToDrive(token, sede, true);
        }

        // ---------- Respaldo: copia exacta de la USB en la nube ----------

        // Ruta relativa con "/" -> ruta local. Incluye txt vigentes e historial de las 3 categorias, Excel consolidado y config.
        private Dictionary<string, string> CollectBackupFiles()
        {
            Dictionary<string, string> res = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string root = baseDir.TrimEnd('\\') + "\\";
            foreach (string cat in new string[] { "ADMINISTRATIVOS", "AULAS", "LABORATORIO" })
            {
                string dir = Path.Combine(baseDir, cat);
                if (!Directory.Exists(dir)) continue;
                List<string> files = new List<string>();
                CollectTxtFilesSafe(dir, files, 0);
                foreach (string f in files)
                    if (f.StartsWith(root, StringComparison.OrdinalIgnoreCase)) res[f.Substring(root.Length).Replace('\\', '/')] = f;
            }
            try
            {
                foreach (string f in Directory.GetFiles(baseDir, "Inventario_Consolidado*.xlsx"))
                    if (!Path.GetFileName(f).StartsWith("~$")) res[Path.GetFileName(f)] = f;
            }
            catch { }
            if (File.Exists(configPath)) res[Path.GetFileName(configPath)] = configPath;
            return res;
        }

        private static void ListRemoteTree(string token, string folderId, string prefix, Dictionary<string, RemoteEntry> files,
            Dictionary<string, RemoteEntry> folders, List<RemoteEntry> duplicados, int depth)
        {
            if (depth > 8) return;
            foreach (Dictionary<string, object> f in DriveList(token, string.Format("'{0}' in parents and trashed=false", DriveQ(folderId)), "id,name,mimeType,md5Checksum"))
            {
                string name = Convert.ToString(f["name"]);
                string rel = prefix.Length == 0 ? name : prefix + "/" + name;
                RemoteEntry e = new RemoteEntry();
                e.Id = Convert.ToString(f["id"]);
                e.ParentId = folderId;
                e.Md5 = f.ContainsKey("md5Checksum") ? Convert.ToString(f["md5Checksum"]) : null;
                if (Convert.ToString(f["mimeType"]) == FOLDER_MIME)
                {
                    if (folders.ContainsKey(rel)) { duplicados.Add(e); continue; }
                    folders[rel] = e;
                    ListRemoteTree(token, e.Id, rel, files, folders, duplicados, depth + 1);
                }
                else if (files.ContainsKey(rel)) duplicados.Add(e);
                else files[rel] = e;
            }
        }

        private void BackupToDriveMenu()
        {
            string token = GetGoogleAccessToken();
            if (token == null) return;
            DriveSede sede;
            try { sede = ChooseDriveSede(token, false); }
            catch (Exception ex)
            {
                MessageBox.Show("No se pudo leer Google Drive:\n" + ex.Message, "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (sede == null) return;
            DialogResult dr = MessageBox.Show(string.Format(
                "Se dejar\u00E1 la carpeta Respaldo de la sede {0} igual a esta USB:\n\n" +
                "\u2022 se suben los reportes, el historial, el Excel consolidado y la configuraci\u00F3n nuevos o cambiados;\n" +
                "\u2022 lo que ya no est\u00E1 en la USB se manda a la papelera de Drive (recuperable 30 d\u00EDas).\n\n\u00BFContinuar?",
                sede.Key.Replace("/", " / ")), "Respaldar en la nube", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (dr == DialogResult.Yes) SyncBackupToDrive(token, sede, false);
        }

        private void SyncBackupToDrive(string token, DriveSede sede, bool trasImportar)
        {
            int subidos = 0, actualizados = 0, iguales = 0, borrados = 0;
            List<string> errores = new List<string>();
            this.Cursor = Cursors.WaitCursor;
            try
            {
                lblStatusText.Text = "Respaldo: revisando la nube...";
                Application.DoEvents();
                string respId = GetSedeSubfolder(token, sede, "respaldo", "Respaldo");
                Dictionary<string, RemoteEntry> rFiles = new Dictionary<string, RemoteEntry>(StringComparer.OrdinalIgnoreCase);
                Dictionary<string, RemoteEntry> rFolders = new Dictionary<string, RemoteEntry>(StringComparer.OrdinalIgnoreCase);
                List<RemoteEntry> duplicados = new List<RemoteEntry>();
                ListRemoteTree(token, respId, "", rFiles, rFolders, duplicados, 0);
                Dictionary<string, string> local = CollectBackupFiles();

                int i = 0;
                foreach (KeyValuePair<string, string> kv in local.OrderBy(x => x.Key))
                {
                    i++;
                    try
                    {
                        RemoteEntry re;
                        string md5 = Md5Hex(kv.Value);
                        if (rFiles.TryGetValue(kv.Key, out re))
                        {
                            if (md5 != null && re.Md5 != null && string.Equals(md5, re.Md5, StringComparison.OrdinalIgnoreCase)) { iguales++; continue; }
                            lblStatusText.Text = string.Format("Respaldo ({0}/{1}): actualizando {2}", i, local.Count, kv.Key);
                            Application.DoEvents();
                            DriveUploadFile(token, re.Id, null, Path.GetFileName(kv.Value), File.ReadAllBytes(kv.Value));
                            actualizados++;
                        }
                        else
                        {
                            lblStatusText.Text = string.Format("Respaldo ({0}/{1}): subiendo {2}", i, local.Count, kv.Key);
                            Application.DoEvents();
                            // Crear las carpetas que falten (ADMINISTRATIVOS/SAE/...)
                            string parent = respId;
                            string acc = "";
                            string[] parts = kv.Key.Split('/');
                            for (int p = 0; p < parts.Length - 1; p++)
                            {
                                acc = acc.Length == 0 ? parts[p] : acc + "/" + parts[p];
                                RemoteEntry fe;
                                if (!rFolders.TryGetValue(acc, out fe))
                                {
                                    fe = new RemoteEntry();
                                    fe.Id = DriveCreateFolderP(token, parts[p], parent, null);
                                    fe.ParentId = parent;
                                    rFolders[acc] = fe;
                                }
                                parent = fe.Id;
                            }
                            DriveUploadFile(token, null, parent, parts[parts.Length - 1], File.ReadAllBytes(kv.Value));
                            subidos++;
                        }
                    }
                    catch (Exception ex) { errores.Add(kv.Key + ": " + ex.Message); }
                }

                // Copia exacta: lo que ya no esta en la USB se quita del Respaldo
                foreach (KeyValuePair<string, RemoteEntry> kv in rFiles)
                {
                    if (local.ContainsKey(kv.Key)) continue;
                    string err = DriveRemove(token, kv.Value.Id, kv.Value.ParentId);
                    if (err == null) borrados++; else errores.Add("No se pudo quitar " + kv.Key + ": " + err);
                }
                foreach (RemoteEntry d in duplicados)
                {
                    string err = DriveRemove(token, d.Id, d.ParentId);
                    if (err == null) borrados++;
                }
                // Carpetas que quedaron sin ningun archivo de la USB (solo la mas alta de cada rama)
                List<string> vacias = rFolders.Keys.Where(f => !local.Keys.Any(l => l.StartsWith(f + "/", StringComparison.OrdinalIgnoreCase)))
                    .OrderBy(f => f.Length).ToList();
                List<string> quitadas = new List<string>();
                foreach (string f in vacias)
                {
                    if (quitadas.Any(q => f.StartsWith(q + "/", StringComparison.OrdinalIgnoreCase))) continue;
                    if (DriveRemove(token, rFolders[f].Id, rFolders[f].ParentId) == null) quitadas.Add(f);
                }
            }
            catch (Exception ex)
            {
                errores.Add(ex.Message);
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }

            string resumen = string.Format("Respaldo de la sede {0}:\n\nSubidos: {1}   Actualizados: {2}   Sin cambios: {3}   Quitados: {4}",
                sede.Key.Replace("/", " / "), subidos, actualizados, iguales, borrados);
            lblStatusText.Text = string.Format("Respaldo en la nube: {0} subido(s), {1} actualizado(s), {2} quitado(s).", subidos, actualizados, borrados);
            if (errores.Count > 0)
                MessageBox.Show(resumen + "\n\nAvisos:\n" + string.Join("\n", errores.Take(12).ToArray()) +
                    (errores.Count > 12 ? string.Format("\n... y {0} m\u00E1s", errores.Count - 12) : ""),
                    "Respaldar en la nube", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            else if (!trasImportar || subidos + actualizados + borrados > 0)
                MessageBox.Show(resumen, "Respaldar en la nube", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // ---------- Administracion (solo el responsable, dueno de la carpeta raiz) ----------

        private string FindOrCreateDriveRoot(string token)
        {
            List<Dictionary<string, object>> found = DriveList(token, string.Format(
                "mimeType='{0}' and name='{1}' and trashed=false and 'me' in owners", FOLDER_MIME, DriveQ(GDRIVE_FOLDER)), "id,properties");
            if (found.Count > 0)
            {
                string id = Convert.ToString(found[0]["id"]);
                if (!found[0].ContainsKey("properties"))
                {
                    Dictionary<string, object> m = new Dictionary<string, object>();
                    m["properties"] = Props("raiz", null);
                    GoogleRequest("PATCH", GDRIVE_API + "files/" + Uri.EscapeDataString(id) + "?fields=id", token, "application/json; charset=UTF-8",
                        Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(m)));
                }
                return id;
            }
            DialogResult dr = MessageBox.Show(string.Format(
                "No tienes la carpeta \"{0}\" en tu Google Drive ({1}).\n\n\u00BFCrearla con las carpetas de CARRION y WIENER y sus sedes?\n\n" +
                "Hazlo solo si eres el RESPONSABLE del inventario.", GDRIVE_FOLDER, gUserEmail), "Google Drive", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (dr != DialogResult.Yes) return null;
            return DriveCreateFolderP(token, GDRIVE_FOLDER, null, Props("raiz", null));
        }

        private static string EnsureInstFolder(string token, string rootId, string inst)
        {
            List<Dictionary<string, object>> f = DriveList(token, string.Format("'{0}' in parents and mimeType='{1}' and trashed=false and {2}",
                DriveQ(rootId), FOLDER_MIME, PropQ("invKey", inst)), "id");
            if (f.Count > 0) return Convert.ToString(f[0]["id"]);
            return DriveCreateFolderP(token, inst, rootId, Props("inst", inst));
        }

        private static DriveSede CreateDriveSede(string token, string rootId, string key)
        {
            string[] p = key.Split('/');
            string instId = EnsureInstFolder(token, rootId, p[0]);
            DriveSede s = new DriveSede();
            s.Key = key;
            s.Owned = true;
            s.Id = DriveCreateFolderP(token, p[1], instId, Props("sede", key));
            GetSedeSubfolder(token, s, "respaldo", "Respaldo");
            GetSedeSubfolder(token, s, "pendientes", "Pendientes");
            return s;
        }

        private class DrivePermission
        {
            public string Id;
            public string Email;
            public string Role;
        }

        private static List<DrivePermission> ListPermissions(string token, string fileId)
        {
            List<DrivePermission> res = new List<DrivePermission>();
            Dictionary<string, object> r = GoogleRequest("GET", GDRIVE_API + "files/" + Uri.EscapeDataString(fileId) +
                "/permissions?fields=" + Uri.EscapeDataString("permissions(id,emailAddress,role,type)"), token, null, null);
            System.Collections.IEnumerable list = r.ContainsKey("permissions") ? r["permissions"] as System.Collections.IEnumerable : null;
            if (list != null)
                foreach (object o in list)
                {
                    Dictionary<string, object> d = o as Dictionary<string, object>;
                    if (d == null) continue;
                    string role = Convert.ToString(d["role"]);
                    if (role == "owner") continue;
                    DrivePermission p = new DrivePermission();
                    p.Id = Convert.ToString(d["id"]);
                    p.Email = d.ContainsKey("emailAddress") ? Convert.ToString(d["emailAddress"]) : Convert.ToString(d["type"]);
                    p.Role = role == "writer" ? "Editor" : (role == "reader" ? "Lector" : role);
                    res.Add(p);
                }
            return res.OrderBy(x => x.Email).ToList();
        }

        private void ShowDriveAdmin()
        {
            string token = GetGoogleAccessToken();
            if (token == null) return;
            string rootId;
            List<DriveSede> sedes;
            this.Cursor = Cursors.WaitCursor;
            try
            {
                rootId = FindOrCreateDriveRoot(token);
                if (rootId == null) return;
                sedes = ListDriveSedes(token, true);
                if (sedes.Count == 0)
                {
                    foreach (string k in SEDES_POR_DEFECTO)
                    {
                        lblStatusText.Text = "Creando sede " + k.Replace("/", " / ") + "...";
                        Application.DoEvents();
                        sedes.Add(CreateDriveSede(token, rootId, k));
                    }
                    lblStatusText.Text = "Estructura de sedes creada en Google Drive.";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("No se pudo preparar la carpeta del inventario en Google Drive:\n" + ex.Message, "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }

            using (Form dlg = new Form())
            {
                dlg.Text = "Google Drive: sedes y t\u00E9cnicos";
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false;
                dlg.MinimizeBox = false;
                dlg.ShowInTaskbar = false;
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.ClientSize = new Size(720, 470);
                dlg.Font = new Font("Segoe UI", 9.5F);
                if (this.Icon != null) dlg.Icon = this.Icon;

                Label l1 = new Label();
                l1.Text = "Sedes";
                l1.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
                l1.Location = new Point(14, 12);
                l1.AutoSize = true;
                ListBox lstSedes = new ListBox();
                lstSedes.Location = new Point(16, 36);
                lstSedes.Size = new Size(230, 340);
                foreach (DriveSede s in sedes) lstSedes.Items.Add(s.Key.Replace("/", " / "));

                Label l2 = new Label();
                l2.Text = "T\u00E9cnicos con acceso a la sede (Editor)";
                l2.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
                l2.Location = new Point(262, 12);
                l2.AutoSize = true;
                ListView lv = new ListView();
                lv.View = View.Details;
                lv.FullRowSelect = true;
                lv.HideSelection = false;
                lv.Location = new Point(264, 36);
                lv.Size = new Size(440, 280);
                lv.Columns.Add("Gmail", 320);
                lv.Columns.Add("Permiso", 100);

                Button bAdd = new Button();
                bAdd.Text = "Agregar t\u00E9cnico...";
                bAdd.Size = new Size(150, 30);
                bAdd.Location = new Point(264, 324);
                Button bDel = new Button();
                bDel.Text = "Quitar acceso";
                bDel.Size = new Size(130, 30);
                bDel.Location = new Point(420, 324);
                Button bSede = new Button();
                bSede.Text = "Agregar sede...";
                bSede.Size = new Size(230, 30);
                bSede.Location = new Point(16, 384);

                Label note = new Label();
                note.Text = "Cada t\u00E9cnico debe estar tambi\u00E9n en \"Usuarios de prueba\" del proyecto de Google Cloud; si no, Google le bloquear\u00E1 el inicio de sesi\u00F3n.";
                note.ForeColor = Color.FromArgb(146, 64, 14);
                note.Location = new Point(264, 362);
                note.Size = new Size(440, 40);

                Button bClose = new Button();
                bClose.Text = "Cerrar";
                bClose.DialogResult = DialogResult.Cancel;
                bClose.Size = new Size(110, 32);
                bClose.Location = new Point(594, 424);
                dlg.CancelButton = bClose;

                List<DrivePermission> perms = new List<DrivePermission>();
                MethodInvoker cargar = delegate
                {
                    lv.Items.Clear();
                    perms.Clear();
                    if (lstSedes.SelectedIndex < 0) return;
                    dlg.Cursor = Cursors.WaitCursor;
                    try
                    {
                        perms.AddRange(ListPermissions(token, sedes[lstSedes.SelectedIndex].Id));
                        foreach (DrivePermission p in perms) lv.Items.Add(new ListViewItem(new string[] { p.Email, p.Role }));
                    }
                    catch (Exception ex) { MessageBox.Show(dlg, "No se pudieron leer los permisos:\n" + ex.Message, "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Error); }
                    finally { dlg.Cursor = Cursors.Default; }
                };
                lstSedes.SelectedIndexChanged += delegate { cargar(); };

                bAdd.Click += delegate
                {
                    if (lstSedes.SelectedIndex < 0) return;
                    DriveSede s = sedes[lstSedes.SelectedIndex];
                    string mail = PromptInput("Agregar t\u00E9cnico", string.Format("Gmail del t\u00E9cnico para la sede {0}:", s.Key.Replace("/", " / ")), "");
                    if (string.IsNullOrWhiteSpace(mail)) return;
                    mail = mail.Trim().ToLowerInvariant();
                    if (!Regex.IsMatch(mail, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
                    {
                        MessageBox.Show(dlg, "Ese correo no es v\u00E1lido.", "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                    try
                    {
                        Dictionary<string, object> body = new Dictionary<string, object>();
                        body["type"] = "user";
                        body["role"] = "writer";
                        body["emailAddress"] = mail;
                        GoogleRequest("POST", GDRIVE_API + "files/" + Uri.EscapeDataString(s.Id) + "/permissions?sendNotificationEmail=true&fields=id",
                            token, "application/json; charset=UTF-8", Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(body)));
                        cargar();
                    }
                    catch (Exception ex) { MessageBox.Show(dlg, "No se pudo dar acceso:\n" + ex.Message, "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Error); }
                };

                bDel.Click += delegate
                {
                    if (lstSedes.SelectedIndex < 0 || lv.SelectedIndices.Count == 0) return;
                    DriveSede s = sedes[lstSedes.SelectedIndex];
                    DrivePermission p = perms[lv.SelectedIndices[0]];
                    if (MessageBox.Show(dlg, string.Format("\u00BFQuitar el acceso de {0} a la sede {1}?", p.Email, s.Key.Replace("/", " / ")),
                        "Google Drive", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                    try
                    {
                        GoogleRequest("DELETE", GDRIVE_API + "files/" + Uri.EscapeDataString(s.Id) + "/permissions/" + Uri.EscapeDataString(p.Id), token, null, null);
                        cargar();
                    }
                    catch (Exception ex) { MessageBox.Show(dlg, "No se pudo quitar el acceso:\n" + ex.Message, "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Error); }
                };

                bSede.Click += delegate
                {
                    string inst = PromptInput("Agregar sede", "Instituci\u00F3n (CARRION o WIENER):", "CARRION");
                    if (string.IsNullOrWhiteSpace(inst)) return;
                    inst = SafeFolderName(inst);
                    string nom = PromptInput("Agregar sede", "Nombre de la sede (ej. SJL, LOCAL 1):", "");
                    if (string.IsNullOrWhiteSpace(nom)) return;
                    string key = inst + "/" + SafeFolderName(nom).Replace("/", "-");
                    if (sedes.Any(x => string.Equals(x.Key, key, StringComparison.OrdinalIgnoreCase)))
                    {
                        MessageBox.Show(dlg, "Esa sede ya existe.", "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        return;
                    }
                    try
                    {
                        DriveSede s = CreateDriveSede(token, rootId, key);
                        sedes.Add(s);
                        sedes.Sort((a, b) => string.Compare(a.Key, b.Key, StringComparison.OrdinalIgnoreCase));
                        lstSedes.Items.Clear();
                        foreach (DriveSede x in sedes) lstSedes.Items.Add(x.Key.Replace("/", " / "));
                        lstSedes.SelectedIndex = sedes.IndexOf(s);
                    }
                    catch (Exception ex) { MessageBox.Show(dlg, "No se pudo crear la sede:\n" + ex.Message, "Google Drive", MessageBoxButtons.OK, MessageBoxIcon.Error); }
                };

                dlg.Controls.AddRange(new Control[] { l1, lstSedes, l2, lv, bAdd, bDel, bSede, note, bClose });
                dlg.Shown += delegate { if (lstSedes.Items.Count > 0) lstSedes.SelectedIndex = 0; };
                dlg.ShowDialog(this);
            }
        }

        private bool IsRemovableBaseDir()
        {
            try
            {
                if (baseDir.StartsWith(@"\\")) return false;
                return new DriveInfo(Path.GetPathRoot(baseDir)).DriveType == DriveType.Removable;
            }
            catch { return false; }
        }

        // Tras GUARDAR: si el programa NO corre desde una USB (equipo con la USB bloqueada), ofrece subir el reporte
        private void OfferDriveUploadAfterSave()
        {
            string path = lastSavedReportPath;
            if (!GoogleConfigured() || !preguntarSubirDrive || string.IsNullOrEmpty(path) || !File.Exists(path)) return;
            if (IsRemovableBaseDir()) return;
            using (Form dlg = new Form())
            {
                dlg.Text = "Google Drive";
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false;
                dlg.MinimizeBox = false;
                dlg.ShowInTaskbar = false;
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.ClientSize = new Size(440, 150);
                dlg.Font = new Font("Segoe UI", 9.5F);
                Label lbl = new Label();
                lbl.Text = "\u00BFSubir este reporte a Google Drive?\n\n\u00DAsalo si este equipo tiene la USB bloqueada: luego se importa a la USB de la sede con Google Drive > Importar pendientes de la sede.";
                lbl.Location = new Point(16, 12);
                lbl.Size = new Size(410, 70);
                CheckBox chk = new CheckBox();
                chk.Text = "No volver a preguntar en esta carpeta";
                chk.Location = new Point(18, 112);
                chk.AutoSize = true;
                Button bYes = new Button();
                bYes.Text = "Subir";
                bYes.DialogResult = DialogResult.Yes;
                bYes.Size = new Size(90, 30);
                bYes.Location = new Point(242, 84);
                Button bNo = new Button();
                bNo.Text = "No";
                bNo.DialogResult = DialogResult.No;
                bNo.Size = new Size(90, 30);
                bNo.Location = new Point(338, 84);
                dlg.AcceptButton = bYes;
                dlg.CancelButton = bNo;
                dlg.Controls.AddRange(new Control[] { lbl, chk, bYes, bNo });
                DialogResult dr = dlg.ShowDialog(this);
                if (chk.Checked)
                {
                    preguntarSubirDrive = false;
                    SaveConfig();
                }
                if (dr == DialogResult.Yes) UploadReportToDrive(path);
            }
        }

        // ===================== Archivo: importar reportes de otros equipos =====================
        // Para equipos con la USB bloqueada: el programa se ejecuta en ese equipo desde una carpeta de red o descargado
        // del release, el .txt se trae por red / correo / Teams / OneDrive y aqui se incorpora a la USB: cada reporte va a
        // su carpeta (CATEGORIA\AREA) y, si el equipo ya existia, se muestra la comparacion campo por campo.

        private void ImportReportsFromFiles()
        {
            using (OpenFileDialog dlg = new OpenFileDialog())
            {
                dlg.Title = "Importar reportes de inventario (.txt)";
                dlg.Filter = "Reportes de inventario (*.txt)|*.txt";
                dlg.Multiselect = true;
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                ImportReports(new List<string>(dlg.FileNames));
            }
        }

        private void ImportReportsFromFolder()
        {
            using (FolderBrowserDialog dlg = new FolderBrowserDialog())
            {
                dlg.Description = "Elige la carpeta con los reportes .txt a importar (se revisan tambi\u00E9n sus subcarpetas).";
                dlg.ShowNewFolderButton = false;
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                if (PathsEqual(dlg.SelectedPath, baseDir))
                {
                    MessageBox.Show("Esa es la carpeta del programa: sus reportes ya est\u00E1n incluidos.", "Importar", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                List<string> files = new List<string>();
                CollectTxtFilesSafe(dlg.SelectedPath, files, 0);
                if (files.Count == 0)
                {
                    MessageBox.Show("No se encontraron archivos .txt en esa carpeta.", "Importar", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                ImportReports(files);
            }
        }

        // Recorrido recursivo que ignora carpetas sin permiso (ej. System Volume Information si eligen la raiz de una unidad)
        private static void CollectTxtFilesSafe(string dir, List<string> result, int depth)
        {
            if (depth > 6) return;
            try { result.AddRange(Directory.GetFiles(dir, "*.txt")); }
            catch { }
            string[] subs;
            try { subs = Directory.GetDirectories(dir); }
            catch { return; }
            foreach (string s in subs)
            {
                try
                {
                    if ((new DirectoryInfo(s).Attributes & (FileAttributes.System | FileAttributes.Hidden)) != 0) continue;
                }
                catch { continue; }
                CollectTxtFilesSafe(s, result, depth + 1);
            }
        }

        // Devuelve, por ruta de archivo: "nuevo", "actualizado", "sin cambios", "omitido", "ignorado" o "error"
        private Dictionary<string, string> ImportReports(List<string> files)
        {
            Dictionary<string, string> resultado = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            int nuevos = 0, actualizados = 0, sinCambios = 0, omitidos = 0, ignorados = 0;
            List<string> errores = new List<string>();
            List<string> detalle = new List<string>();

            foreach (string src in files)
            {
                string nombre = Path.GetFileName(src);
                try
                {
                    // Los archivos de historial (con fecha) no son reportes vigentes
                    resultado[src] = "error";
                    if (Regex.IsMatch(Path.GetFileNameWithoutExtension(src), @"_\d{8}_\d{6}$")) { ignorados++; resultado[src] = "ignorado"; continue; }
                    string[] lines = File.ReadAllLines(src, Encoding.UTF8);
                    if (string.Join("\n", lines).IndexOf("INVENTARIO DE HARDWARE Y RED", StringComparison.Ordinal) < 0) { ignorados++; resultado[src] = "ignorado"; continue; }

                    InventoryReport nuevo = ParseReport(lines);
                    string host = nuevo.Get("Hostname").Trim();
                    if (host.Length == 0) { errores.Add(nombre + ": no tiene Hostname"); continue; }

                    string destino = GetReportPath(nuevo);
                    int cantidad;
                    FileInfo previo = FindExistingReport(host, destino, out cantidad);
                    if (previo != null && PathsEqual(previo.FullName, src)) { sinCambios++; resultado[src] = "sin cambios"; continue; }

                    if (previo == null)
                    {
                        WriteReportFile(destino, nuevo);
                        nuevos++;
                        resultado[src] = "nuevo";
                        detalle.Add("NUEVO        " + host + "  ->  " + RelPath(destino));
                        continue;
                    }

                    InventoryReport anterior = ParseReport(File.ReadAllLines(previo.FullName, Encoding.UTF8));
                    List<FieldDiff> diffs = ComputeReportDiffs(anterior, nuevo);
                    if (diffs.Count == 0) { sinCambios++; resultado[src] = "sin cambios"; continue; }

                    int op = ShowFieldDiffDialog(host, previo, cantidad, anterior, destino, diffs);
                    if (op != 1 && op != 2)
                    {
                        omitidos++;
                        resultado[src] = "omitido";
                        detalle.Add("OMITIDO      " + host);
                        continue;
                    }
                    InventoryReport final;
                    ApplyReportSave(previo, anterior, nuevo, diffs, op, out final);
                    actualizados++;
                    resultado[src] = "actualizado";
                    detalle.Add("ACTUALIZADO  " + host + "  ->  " + RelPath(GetReportPath(final)));
                }
                catch (Exception ex)
                {
                    errores.Add(nombre + ": " + ex.Message);
                }
            }

            UpdateTxtCounterBadge();
            if (tableTodos != null && (nuevos + actualizados) > 0) LoadTxtFilesIntoTable();

            StringBuilder sb = new StringBuilder();
            sb.AppendLine(string.Format("Nuevos: {0}   Actualizados: {1}   Sin cambios: {2}   Omitidos: {3}", nuevos, actualizados, sinCambios, omitidos));
            if (ignorados > 0) sb.AppendLine(string.Format("No son reportes vigentes (otros .txt o historial con fecha): {0}", ignorados));
            if (detalle.Count > 0)
            {
                sb.AppendLine();
                foreach (string d in detalle.Take(25)) sb.AppendLine(d);
                if (detalle.Count > 25) sb.AppendLine(string.Format("... y {0} m\u00E1s", detalle.Count - 25));
            }
            if (errores.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Errores:");
                foreach (string er in errores.Take(15)) sb.AppendLine("  " + er);
            }
            lblStatusText.Text = string.Format("Importaci\u00F3n: {0} nuevo(s), {1} actualizado(s), {2} sin cambios.", nuevos, actualizados, sinCambios);
            MessageBox.Show(sb.ToString(), "Importar reportes", MessageBoxButtons.OK,
                errores.Count > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            return resultado;
        }

        private void OpenLastReportFolder()
        {
            try
            {
                if (!string.IsNullOrEmpty(lastSavedReportPath) && File.Exists(lastSavedReportPath))
                    Process.Start("explorer.exe", "/select,\"" + lastSavedReportPath + "\"");
                else
                    Process.Start("explorer.exe", "\"" + baseDir + "\"");
            }
            catch (Exception ex)
            {
                MessageBox.Show("No se pudo abrir la carpeta:\n" + ex.Message, "Abrir carpeta", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        // ===================== Actualizaciones (releases publicos de GitHub) =====================
        // Consulta el ultimo release del repo publico (sin token). Si hay una version mayor muestra las novedades y,
        // si el tecnico acepta, descarga el ZIP del release, verifica su SHA-256 (el "digest" que publica GitHub),
        // reemplaza InventarioTI.exe e Iniciar_Inventario.bat en la carpeta del programa y lo vuelve a abrir.
        // Los reportes, config_inventario.json y los .xlsx no se tocan.

        private const string UPDATE_API = "https://api.github.com/repos/aarneth/inventario-ti/releases/latest";
        private const string UPDATE_UA = "InventarioTI-Updater";
        private bool updateDialogOpen = false;

        private class UpdateInfo
        {
            public Version Version;
            public string Tag;
            public string Notes;
            public string ZipUrl;
            public string ZipName;
            public string Sha256;   // null si GitHub no publica el digest
            public string PageUrl;
        }

        private static Version CurrentVersion()
        {
            Version v = Assembly.GetExecutingAssembly().GetName().Version;
            return new Version(v.Major, v.Minor, v.Build);
        }

        private static void EnableTls12()
        {
            // .NET Framework 4.x no siempre habilita TLS 1.2 por defecto; GitHub lo exige
            try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; } catch { }
        }

        // Carpeta con los archivos del programa (raiz de la USB). null = copia de desarrollo: no se actualiza.
        private string GetInstallDir(out string error)
        {
            error = null;
            string dir;
            if (Program.IsExe)
            {
                dir = Path.GetDirectoryName(Application.ExecutablePath);
            }
            else
            {
                // El .bat autonomo del release define INV_SELF; el .bat del proyecto (con carpeta src) no
                string self = Environment.GetEnvironmentVariable("INV_SELF");
                if (string.IsNullOrEmpty(self))
                {
                    error = "Esta es la copia de desarrollo (Iniciar_Inventario.bat que usa la carpeta src). Las actualizaciones autom\u00E1ticas solo funcionan con el paquete del release.";
                    return null;
                }
                dir = Path.GetDirectoryName(self);
            }
            if (File.Exists(Path.Combine(Path.Combine(dir, "src"), "InventarioApp.cs")))
            {
                error = "Esta es la carpeta del proyecto (contiene src\\InventarioApp.cs). Las actualizaciones autom\u00E1ticas solo funcionan con el paquete del release copiado en la USB.";
                return null;
            }
            return dir;
        }

        private static UpdateInfo FetchLatestRelease()
        {
            EnableTls12();
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(UPDATE_API);
            req.UserAgent = UPDATE_UA;
            req.Accept = "application/vnd.github+json";
            req.Timeout = 8000;
            req.ReadWriteTimeout = 8000;
            string json;
            using (WebResponse resp = req.GetResponse())
            using (StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
            {
                json = sr.ReadToEnd();
            }

            JavaScriptSerializer ser = new JavaScriptSerializer();
            ser.MaxJsonLength = int.MaxValue;
            Dictionary<string, object> root = ser.Deserialize<Dictionary<string, object>>(json);
            if (root == null) return null;

            UpdateInfo info = new UpdateInfo();
            info.Tag = root.ContainsKey("tag_name") ? Convert.ToString(root["tag_name"]) : "";
            Match mv = Regex.Match(info.Tag, @"(\d+)\.(\d+)\.(\d+)");
            if (!mv.Success) return null;
            info.Version = new Version(int.Parse(mv.Groups[1].Value), int.Parse(mv.Groups[2].Value), int.Parse(mv.Groups[3].Value));
            info.Notes = root.ContainsKey("body") ? Convert.ToString(root["body"]) : "";
            info.PageUrl = root.ContainsKey("html_url") ? Convert.ToString(root["html_url"]) : "";

            System.Collections.IEnumerable assets = root.ContainsKey("assets") ? root["assets"] as System.Collections.IEnumerable : null;
            if (assets != null)
            {
                foreach (object o in assets)
                {
                    Dictionary<string, object> a = o as Dictionary<string, object>;
                    if (a == null) continue;
                    string name = a.ContainsKey("name") ? Convert.ToString(a["name"]) : "";
                    if (!Regex.IsMatch(name, @"^InventarioTI_v[\d.]+\.zip$", RegexOptions.IgnoreCase)) continue;
                    info.ZipName = name;
                    info.ZipUrl = a.ContainsKey("browser_download_url") ? Convert.ToString(a["browser_download_url"]) : "";
                    string dg = a.ContainsKey("digest") && a["digest"] != null ? Convert.ToString(a["digest"]) : "";
                    if (dg.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)) info.Sha256 = dg.Substring(7).Trim().ToLowerInvariant();
                    break;
                }
            }
            if (string.IsNullOrEmpty(info.ZipUrl)) return null;
            return info;
        }

        // Al abrir: busca en segundo plano y solo avisa si hay una version nueva (sin internet = silencioso)
        private void CheckForUpdatesInBackground()
        {
            string err;
            if (GetInstallDir(out err) == null) return;
            Thread th = new Thread(delegate()
            {
                UpdateInfo info = null;
                try { info = FetchLatestRelease(); }
                catch { }
                if (info == null || info.Version <= CurrentVersion()) return;
                try { this.BeginInvoke((MethodInvoker)delegate { OfferUpdate(info); }); }
                catch { }
            });
            th.IsBackground = true;
            th.Start();
        }

        private void CheckForUpdatesManual()
        {
            this.Cursor = Cursors.WaitCursor;
            lblStatusText.Text = "Buscando actualizaciones...";
            Application.DoEvents();
            UpdateInfo info = null;
            string error = null;
            try { info = FetchLatestRelease(); }
            catch (Exception ex) { error = ex.Message; }
            finally { this.Cursor = Cursors.Default; }

            if (error != null)
            {
                lblStatusText.Text = "No se pudo buscar actualizaciones.";
                MessageBox.Show("No se pudo consultar si hay una versi\u00F3n nueva. Verifica la conexi\u00F3n a internet.\n\nDetalle: " + error,
                    "Buscar actualizaciones", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (info == null)
            {
                lblStatusText.Text = "No se encontr\u00F3 un paquete de actualizaci\u00F3n.";
                MessageBox.Show("El \u00FAltimo release publicado no tiene un paquete InventarioTI_v*.zip.",
                    "Buscar actualizaciones", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (info.Version <= CurrentVersion())
            {
                lblStatusText.Text = string.Format("Ya tienes la \u00FAltima versi\u00F3n (v{0}).", CurrentVersion());
                MessageBox.Show(string.Format("Ya tienes la \u00FAltima versi\u00F3n (v{0}).", CurrentVersion()),
                    "Buscar actualizaciones", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            OfferUpdate(info);
        }

        // Las notas del release vienen en Markdown: se limpian para mostrarlas como texto plano
        private static string ReleaseNotesToText(string md)
        {
            List<string> res = new List<string>();
            foreach (string raw in (md ?? "").Replace("\r\n", "\n").Split('\n'))
            {
                string l = raw.TrimEnd();
                if (l.IndexOf("Generated with", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                if (Regex.IsMatch(l, @"^\|?\s*-{3,}")) continue;
                l = Regex.Replace(l, @"^#+\s*", "");
                l = Regex.Replace(l, @"^(\s*)[-*]\s+", "$1\u2022 ");
                l = l.Replace("**", "").Replace("`", "");
                l = Regex.Replace(l, @"\[([^\]]+)\]\([^)]+\)", "$1");
                if (l.StartsWith("|")) l = l.Trim('|').Replace(" | ", "  -  ").Trim();
                res.Add(l);
            }
            return string.Join("\r\n", res.ToArray()).Trim();
        }

        private void OfferUpdate(UpdateInfo info)
        {
            if (updateDialogOpen) return;
            updateDialogOpen = true;
            try
            {
                using (Form dlg = new Form())
                {
                    dlg.Text = "Actualizaci\u00F3n disponible";
                    dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                    dlg.MaximizeBox = false;
                    dlg.MinimizeBox = false;
                    dlg.ShowInTaskbar = false;
                    dlg.StartPosition = FormStartPosition.CenterParent;
                    dlg.ClientSize = new Size(600, 460);
                    dlg.Font = new Font("Segoe UI", 9.5F);
                    if (this.Icon != null) dlg.Icon = this.Icon;

                    Label t1 = new Label();
                    t1.Text = string.Format("Hay una versi\u00F3n nueva: v{0}   (tienes la v{1})", info.Version, CurrentVersion());
                    t1.Font = new Font("Segoe UI", 12F, FontStyle.Bold);
                    t1.ForeColor = Color.FromArgb(15, 23, 42);
                    t1.AutoSize = true;
                    t1.Location = new Point(16, 14);

                    Label t2 = new Label();
                    t2.Text = "Novedades:";
                    t2.AutoSize = true;
                    t2.Location = new Point(18, 48);

                    TextBox txt = new TextBox();
                    txt.Multiline = true;
                    txt.ReadOnly = true;
                    txt.ScrollBars = ScrollBars.Vertical;
                    txt.BackColor = Color.White;
                    txt.Location = new Point(18, 70);
                    txt.Size = new Size(564, 280);
                    txt.Text = ReleaseNotesToText(info.Notes);
                    txt.SelectionStart = 0;

                    Label t3 = new Label();
                    t3.Text = "Se reemplazar\u00E1n InventarioTI.exe e Iniciar_Inventario.bat en la carpeta del programa y se volver\u00E1 a abrir. " +
                        "Los reportes .txt, la configuraci\u00F3n y los Excel no se modifican.";
                    t3.ForeColor = Color.FromArgb(71, 85, 105);
                    t3.Location = new Point(18, 360);
                    t3.Size = new Size(564, 40);

                    Button bOk = new Button();
                    bOk.Text = "Actualizar ahora";
                    bOk.DialogResult = DialogResult.OK;
                    bOk.Size = new Size(150, 32);
                    bOk.Location = new Point(276, 412);
                    bOk.BackColor = Color.FromArgb(37, 99, 235);
                    bOk.ForeColor = Color.White;
                    bOk.FlatStyle = FlatStyle.Flat;

                    Button bNo = new Button();
                    bNo.Text = "Ahora no";
                    bNo.DialogResult = DialogResult.Cancel;
                    bNo.Size = new Size(150, 32);
                    bNo.Location = new Point(432, 412);

                    dlg.AcceptButton = bOk;
                    dlg.CancelButton = bNo;
                    dlg.Controls.AddRange(new Control[] { t1, t2, txt, t3, bOk, bNo });
                    if (dlg.ShowDialog(this) != DialogResult.OK) return;
                }
                InstallUpdate(info);
            }
            finally
            {
                updateDialogOpen = false;
            }
        }

        private static string FileSha256(string path)
        {
            using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
            using (FileStream fs = File.OpenRead(path))
            {
                byte[] h = sha.ComputeHash(fs);
                StringBuilder sb = new StringBuilder();
                foreach (byte b in h) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        private bool DownloadWithProgress(string url, string dest, Version ver)
        {
            EnableTls12();
            bool ok = false;
            string error = null;
            using (Form dlg = new Form())
            using (WebClient wc = new WebClient())
            {
                dlg.Text = "Descargando actualizaci\u00F3n";
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.ControlBox = false;
                dlg.ShowInTaskbar = false;
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.ClientSize = new Size(420, 120);
                dlg.Font = new Font("Segoe UI", 9.5F);

                Label lbl = new Label();
                lbl.Text = string.Format("Descargando la versi\u00F3n v{0}...", ver);
                lbl.AutoSize = true;
                lbl.Location = new Point(18, 16);
                ProgressBar pb = new ProgressBar();
                pb.Location = new Point(20, 44);
                pb.Size = new Size(380, 22);
                Button bCancel = new Button();
                bCancel.Text = "Cancelar";
                bCancel.Size = new Size(100, 28);
                bCancel.Location = new Point(300, 80);
                bCancel.Click += delegate { wc.CancelAsync(); };
                dlg.Controls.AddRange(new Control[] { lbl, pb, bCancel });

                wc.Headers[HttpRequestHeader.UserAgent] = UPDATE_UA;
                wc.DownloadProgressChanged += delegate(object s, DownloadProgressChangedEventArgs e) {
                    pb.Value = Math.Max(0, Math.Min(100, e.ProgressPercentage));
                };
                wc.DownloadFileCompleted += delegate(object s, System.ComponentModel.AsyncCompletedEventArgs e) {
                    if (e.Cancelled) error = null;
                    else if (e.Error != null) error = e.Error.Message;
                    else ok = true;
                    dlg.Close();
                };
                dlg.Shown += delegate { wc.DownloadFileAsync(new Uri(url), dest); };
                dlg.ShowDialog(this);
            }
            if (!ok && error != null)
                MessageBox.Show("No se pudo descargar la actualizaci\u00F3n:\n" + error, "Actualizaci\u00F3n", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return ok;
        }

        private void InstallUpdate(UpdateInfo info)
        {
            string err;
            string installDir = GetInstallDir(out err);
            if (installDir == null)
            {
                MessageBox.Show(err, "Actualizaci\u00F3n", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            // Antes de cerrar: guardar o descartar las ediciones pendientes de la tabla
            if (!ConfirmSaveOrDiscardGridChanges()) return;

            string work = Path.Combine(Path.GetTempPath(), "InventarioTI_update");
            string zipPath = Path.Combine(work, info.ZipName);
            string extract = Path.Combine(work, "nuevo");
            try
            {
                if (Directory.Exists(work)) Directory.Delete(work, true);
                Directory.CreateDirectory(work);
            }
            catch (Exception ex)
            {
                MessageBox.Show("No se pudo preparar la carpeta temporal:\n" + ex.Message, "Actualizaci\u00F3n", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            lblStatusText.Text = string.Format("Descargando la versi\u00F3n v{0}...", info.Version);
            if (!DownloadWithProgress(info.ZipUrl, zipPath, info.Version))
            {
                lblStatusText.Text = "Actualizaci\u00F3n cancelada.";
                return;
            }

            string curExe = Path.Combine(installDir, "InventarioTI.exe");
            string curBat = Path.Combine(installDir, "Iniciar_Inventario.bat");
            try
            {
                if (!string.IsNullOrEmpty(info.Sha256) && !string.Equals(FileSha256(zipPath), info.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new Exception("La descarga est\u00E1 da\u00F1ada: su SHA-256 no coincide con el publicado. Intenta nuevamente.");

                ZipFile.ExtractToDirectory(zipPath, extract);
                string newExe = Path.Combine(extract, "InventarioTI.exe");
                string newBat = Path.Combine(extract, "Iniciar_Inventario.bat");
                if (!File.Exists(newExe) || !File.Exists(newBat))
                    throw new Exception("El paquete descargado no contiene InventarioTI.exe e Iniciar_Inventario.bat.");

                // Windows no deja sobrescribir un .exe en ejecucion, pero si renombrarlo. El .old se borra al abrir.
                string oldExe = curExe + ".old";
                if (File.Exists(oldExe)) File.Delete(oldExe);
                if (File.Exists(curExe)) File.Move(curExe, oldExe);
                try { File.Copy(newExe, curExe, true); }
                catch
                {
                    if (!File.Exists(curExe) && File.Exists(oldExe)) File.Move(oldExe, curExe);
                    throw;
                }
                // Si el programa corre desde el .bat, cmd.exe vuelve a leer ese archivo al terminar. La cabecera del
                // .bat (build/empaquetar_release.ps1) es identica en todas las versiones, por eso se puede reemplazar.
                File.Copy(newBat, curBat, true);
            }
            catch (Exception ex)
            {
                lblStatusText.Text = "No se pudo instalar la actualizaci\u00F3n.";
                MessageBox.Show("No se pudo instalar la actualizaci\u00F3n:\n" + ex.Message +
                    "\n\nEl programa sigue en la versi\u00F3n actual. Tambi\u00E9n puedes descargarla manualmente desde:\n" + info.PageUrl,
                    "Actualizaci\u00F3n", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            try { Directory.Delete(work, true); } catch { }

            MessageBox.Show(string.Format("Se instal\u00F3 la versi\u00F3n v{0}. El programa se volver\u00E1 a abrir.", info.Version),
                "Actualizaci\u00F3n completada", MessageBoxButtons.OK, MessageBoxIcon.Information);

            try
            {
                ProcessStartInfo psi;
                if (Program.IsExe)
                {
                    psi = new ProcessStartInfo(curExe);
                }
                else
                {
                    psi = new ProcessStartInfo("cmd.exe", "/c \"\"" + curBat + "\"\"");
                    psi.WindowStyle = ProcessWindowStyle.Minimized;
                }
                psi.WorkingDirectory = installDir;
                psi.UseShellExecute = true;
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                // Tipicamente Kaspersky / Smart App Control bloqueando el .exe nuevo (otro hash) hasta que se apruebe
                MessageBox.Show(string.Format("La versi\u00F3n v{0} qued\u00F3 instalada, pero no se pudo abrir InventarioTI.exe:\n{1}\n\n" +
                    "Puede estar bloqueado por el antivirus hasta que Seguridad TI apruebe el nuevo hash. " +
                    "Mientras tanto, usa Iniciar_Inventario.bat.", info.Version, ex.Message),
                    "Actualizaci\u00F3n", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            cerrandoPorActualizacion = true;
            this.Close();
        }

        // Al abrir la version nueva: borrar el InventarioTI.exe.old que dejo la actualizacion
        private void CleanupAfterUpdate()
        {
            string err;
            string dir = GetInstallDir(out err);
            if (dir == null) return;
            string oldExe = Path.Combine(dir, "InventarioTI.exe.old");
            if (!File.Exists(oldExe)) return;
            Thread th = new Thread(delegate()
            {
                // El proceso anterior puede tardar un momento en cerrarse
                for (int i = 0; i < 20; i++)
                {
                    try { File.Delete(oldExe); return; }
                    catch { Thread.Sleep(500); }
                }
            });
            th.IsBackground = true;
            th.Start();
        }

        // ===================== Ayuda > Acerca de =====================

        private void ShowAboutDialog()
        {
            Version ver = Assembly.GetExecutingAssembly().GetName().Version;
            using (Form dlg = new Form())
            {
                dlg.Text = "Acerca de";
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false;
                dlg.MinimizeBox = false;
                dlg.ShowInTaskbar = false;
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.ClientSize = new Size(520, 470);
                dlg.BackColor = Color.White;
                dlg.Font = new Font("Segoe UI", 9.5F);
                if (this.Icon != null) dlg.Icon = this.Icon;

                Panel head = new Panel();
                head.Dock = DockStyle.Top;
                head.Height = 78;
                head.BackColor = Color.FromArgb(15, 23, 42);
                Label t1 = new Label();
                t1.Text = "Sistema de Inventario y Auditor\u00EDa TI";
                t1.Font = new Font("Segoe UI", 14F, FontStyle.Bold);
                t1.ForeColor = Color.White;
                t1.AutoSize = true;
                t1.Location = new Point(20, 12);
                head.Controls.Add(t1);
                Label t2 = new Label();
                t2.Text = string.Format("Versi\u00F3n {0}.{1}.{2}  \u2022  Universidad Norbert Wiener  |  Instituto Carri\u00F3n", ver.Major, ver.Minor, ver.Build);
                t2.ForeColor = Color.FromArgb(148, 163, 184);
                t2.AutoSize = true;
                t2.Location = new Point(22, 46);
                head.Controls.Add(t2);

                Label lblAutor = new Label();
                lblAutor.Text = "Creado por";
                lblAutor.ForeColor = Color.FromArgb(100, 116, 139);
                lblAutor.AutoSize = true;
                lblAutor.Location = new Point(22, 96);
                Label lblNombre = new Label();
                lblNombre.Text = "Aaron Keneth Gonzales Cortez";
                lblNombre.Font = new Font("Segoe UI", 12F, FontStyle.Bold);
                lblNombre.ForeColor = Color.FromArgb(15, 23, 42);
                lblNombre.AutoSize = true;
                lblNombre.Location = new Point(20, 116);
                Label lblAnio = new Label();
                lblAnio.Text = "A\u00F1o de creaci\u00F3n: 2026";
                lblAnio.AutoSize = true;
                lblAnio.Location = new Point(22, 146);

                Label lblGracias = new Label();
                lblGracias.Text = "\u00A1Gracias por usar este programa! Tu trabajo ayuda a mantener actualizado y confiable " +
                    "el inventario de equipos de c\u00F3mputo de la Universidad Norbert Wiener y del Instituto Carri\u00F3n.";
                lblGracias.ForeColor = Color.FromArgb(30, 64, 175);
                lblGracias.BackColor = Color.FromArgb(239, 246, 255);
                lblGracias.Padding = new Padding(10, 8, 10, 8);
                lblGracias.Location = new Point(20, 178);
                lblGracias.Size = new Size(480, 76);

                Label lblHerr = new Label();
                lblHerr.Text = "Herramientas utilizadas";
                lblHerr.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
                lblHerr.AutoSize = true;
                lblHerr.Location = new Point(20, 268);
                Label lblLista = new Label();
                lblLista.Text =
                    "\u2022  C# 5, .NET Framework 4.x y Windows Forms\n" +
                    "\u2022  WMI / CIM, Registro de Windows, Active Directory (LDAP)\n" +
                    "   y Open XML (Excel sin Microsoft Office)\n" +
                    "\u2022  Claude Code (asistente de programaci\u00F3n con IA de Anthropic)\n" +
                    "\u2022  Git y GitHub (control de versiones y publicaci\u00F3n)";
                lblLista.Location = new Point(22, 292);
                lblLista.Size = new Size(480, 100);

                Label lblCopy = new Label();
                lblCopy.Text = "\u00A9 2026 Aaron Keneth Gonzales Cortez";
                lblCopy.ForeColor = Color.FromArgb(100, 116, 139);
                lblCopy.AutoSize = true;
                lblCopy.Location = new Point(22, 432);

                Button btn = new Button();
                btn.Text = "Cerrar";
                btn.DialogResult = DialogResult.OK;
                btn.Size = new Size(100, 30);
                btn.Location = new Point(400, 424);
                dlg.AcceptButton = btn;
                dlg.CancelButton = btn;

                dlg.Controls.AddRange(new Control[] { head, lblAutor, lblNombre, lblAnio, lblGracias, lblHerr, lblLista, lblCopy, btn });
                dlg.ShowDialog(this);
            }
        }

        // ===================== Deteccion de software de seguridad (Antivirus, Absolute, HP Insights) =====================
        // Todo funciona como usuario estandar: Centro de Seguridad de Windows (root\SecurityCenter2),
        // servicios (Win32_Service), programas instalados (Registro Uninstall) y archivos del sistema.

        private const string SEC_DETECTADO = "Detectado: ";
        private const string SEC_NO_DETECTADO = "No detectado";

        private void ScanSecuritySoftware(out string antivirus, out string absolute, out string hpInsights)
        {
            List<string[]> services = GetServicesList();
            List<string[]> programs = GetInstalledPrograms();
            antivirus = DetectAntivirus(services);
            absolute = DetectAbsolute(services, programs);
            hpInsights = DetectHpInsightsAgent(services, programs);
        }

        // [Nombre, Nombre para mostrar]
        private static List<string[]> GetServicesList()
        {
            List<string[]> res = new List<string[]>();
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT Name, DisplayName FROM Win32_Service"))
                {
                    foreach (ManagementObject mo in s.Get())
                    {
                        string n = mo["Name"] != null ? mo["Name"].ToString().Trim() : "";
                        string d = mo["DisplayName"] != null ? mo["DisplayName"].ToString().Trim() : "";
                        if (n.Length > 0) res.Add(new string[] { n, d });
                    }
                }
            }
            catch { }
            return res;
        }

        // [Nombre del programa, Fabricante] desde las claves Uninstall (64 y 32 bits, equipo y usuario)
        private static List<string[]> GetInstalledPrograms()
        {
            List<string[]> res = new List<string[]>();
            const string UNINST = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            List<RegistryKey> roots = new List<RegistryKey>();
            try { roots.Add(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)); } catch { }
            try { roots.Add(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32)); } catch { }
            try { roots.Add(RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default)); } catch { }
            foreach (RegistryKey root in roots)
            {
                try
                {
                    using (RegistryKey uk = root.OpenSubKey(UNINST))
                    {
                        if (uk == null) continue;
                        foreach (string sub in uk.GetSubKeyNames())
                        {
                            try
                            {
                                using (RegistryKey pk = uk.OpenSubKey(sub))
                                {
                                    if (pk == null) continue;
                                    object dn = pk.GetValue("DisplayName");
                                    if (dn == null || dn.ToString().Trim().Length == 0) continue;
                                    object pb = pk.GetValue("Publisher");
                                    res.Add(new string[] { dn.ToString().Trim(), pb != null ? pb.ToString().Trim() : "" });
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
                finally { root.Close(); }
            }
            return res;
        }

        private static void AddEvidence(List<string> list, string item)
        {
            foreach (string x in list)
                if (string.Equals(x, item, StringComparison.OrdinalIgnoreCase)) return;
            list.Add(item);
        }

        private static string EvidenceResult(List<string> ev)
        {
            if (ev.Count == 0) return SEC_NO_DETECTADO;
            return SEC_DETECTADO + string.Join("; ", ev.Take(4).ToArray());
        }

        // Productos registrados en el Centro de Seguridad de Windows. Si no esta disponible (Windows Server)
        // se buscan los servicios de Kaspersky.
        private static string DetectAntivirus(List<string[]> services)
        {
            List<string> prods = new List<string>();
            bool consultado = false;
            try
            {
                ManagementScope scope = new ManagementScope(@"\\.\root\SecurityCenter2");
                scope.Connect();
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT displayName, productState FROM AntiVirusProduct")))
                {
                    foreach (ManagementObject mo in s.Get())
                    {
                        string name = mo["displayName"] != null ? mo["displayName"].ToString().Trim() : "";
                        if (name.Length == 0) continue;
                        uint state = 0;
                        if (mo["productState"] != null) uint.TryParse(mo["productState"].ToString(), out state);
                        // Bits 12-15 de productState: 1 = proteccion en tiempo real activa
                        string estado = ((state >> 12) & 0xF) == 1 ? "activo" : "inactivo";
                        AddEvidence(prods, string.Format("{0} ({1})", name, estado));
                    }
                }
                consultado = true;
            }
            catch { }

            bool hayKaspersky = prods.Any(p => p.IndexOf("Kaspersky", StringComparison.OrdinalIgnoreCase) >= 0);
            if (!hayKaspersky)
            {
                foreach (string[] sv in services)
                {
                    string d = sv[1];
                    if (d.IndexOf("Kaspersky", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    // El Agente de red (klnagent) es la consola de administracion, no el antivirus
                    if (Regex.IsMatch(d, @"Network Agent|Agente de red", RegexOptions.IgnoreCase)) continue;
                    AddEvidence(prods, string.Format("{0} (servicio)", d));
                    break;
                }
            }

            if (prods.Count > 0) return string.Join(" / ", prods.ToArray());
            return consultado ? "No se detecto antivirus" : "No se pudo consultar el antivirus (validar presencialmente)";
        }

        private static string DetectAbsolute(List<string[]> services, List<string[]> programs)
        {
            List<string> ev = new List<string>();
            foreach (string[] sv in services)
            {
                if (Regex.IsMatch(sv[0], @"^(rpcnet|rpcnetp|ctes.*|absolute.*)$", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(sv[1], @"\bAbsolute\b|Computrace", RegexOptions.IgnoreCase))
                    AddEvidence(ev, "servicio " + (sv[1].Length > 0 ? sv[1] : sv[0]));
            }
            foreach (string[] p in programs)
            {
                if (Regex.IsMatch(p[1], @"Absolute Software", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(p[0], @"^Absolute\b|Computrace", RegexOptions.IgnoreCase))
                    AddEvidence(ev, "programa " + p[0]);
            }
            try
            {
                string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                foreach (string f in new string[] { @"System32\rpcnet.exe", @"System32\rpcnetp.exe", @"SysWOW64\rpcnet.exe", @"SysWOW64\rpcnetp.exe" })
                {
                    if (File.Exists(Path.Combine(win, f))) AddEvidence(ev, "archivo " + Path.GetFileName(f));
                }
            }
            catch { }
            try
            {
                foreach (RegistryView view in new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 })
                {
                    using (RegistryKey lm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                    using (RegistryKey k = lm.OpenSubKey(@"SOFTWARE\Absolute Software"))
                    {
                        if (k != null) AddEvidence(ev, "registro Absolute Software");
                    }
                }
            }
            catch { }
            return EvidenceResult(ev);
        }

        private static string DetectHpInsightsAgent(List<string[]> services, List<string[]> programs)
        {
            const string PATRON = @"^HP\s+(Insights|Touchpoint\s+Analytics|TechPulse)|^HP\b.*Workforce\s+Experience";
            List<string> ev = new List<string>();
            foreach (string[] sv in services)
            {
                if (Regex.IsMatch(sv[1], PATRON, RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(sv[0], @"^(HpTouchpointAnalyticsService|HPInsights.*|HPTechPulse.*)$", RegexOptions.IgnoreCase))
                    AddEvidence(ev, "servicio " + (sv[1].Length > 0 ? sv[1] : sv[0]));
            }
            foreach (string[] p in programs)
            {
                if (Regex.IsMatch(p[0], PATRON, RegexOptions.IgnoreCase))
                    AddEvidence(ev, "programa " + p[0]);
            }
            return EvidenceResult(ev);
        }

        // Valores de las columnas del Excel a partir de lo guardado en el .txt.
        // Campo vacio = reporte generado antes de la v1.2.0 (sin deteccion) => "NO VERIFICADO".
        private const string NO_VERIFICADO = "NO VERIFICADO";

        private static string CalcAntivirusCol(string detectado)
        {
            string d = (detectado ?? "").Trim();
            if (d.Length == 0 || d.IndexOf("validar", StringComparison.OrdinalIgnoreCase) >= 0) return NO_VERIFICADO;
            return d.IndexOf("Kaspersky", StringComparison.OrdinalIgnoreCase) >= 0 ? "S\u00CD" : "NO";
        }

        private static string CalcAgentCol(string detectado)
        {
            string d = (detectado ?? "").Trim();
            if (d.Length == 0) return NO_VERIFICADO;
            return d.StartsWith(SEC_DETECTADO.Trim(), StringComparison.OrdinalIgnoreCase) ? "S\u00CD" : "NO";
        }

        // Tipo de equipo: solo "PC" o "LAPTOP". LAPTOP si el hostname es [W|C][Sede]LP... o el chasis es portatil;
        // todo lo demas (torre, mini PC, all-in-one, chasis no identificado...) = PC.
        private static string NormalizeTipoEquipo(string tipoRaw, string hostName)
        {
            string h = (hostName ?? "").Trim().ToUpperInvariant();
            if (Regex.IsMatch(h, @"^[A-Z]+\d+LP")) return "LAPTOP";
            if (Regex.IsMatch(tipoRaw ?? "", @"Laptop|Portatil|Notebook|Convertible|Tablet|Desmontable|Handheld", RegexOptions.IgnoreCase))
                return "LAPTOP";
            return "PC";
        }

        // ===================== Modelo del reporte .txt (lectura / escritura) =====================

        private static string RptLine(string label, string value)
        {
            return label.PadRight(19) + ": " + (value ?? "");
        }

        private static string OneLine(string s)
        {
            if (s == null) return "";
            return Regex.Replace(s, @"[\r\n]+", " ").Trim();
        }

        private static string[] SplitLines(string text)
        {
            List<string> res = new List<string>();
            foreach (string l in (text ?? "").Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (l.Trim().Length > 0) res.Add(l.Trim());
            }
            return res.ToArray();
        }

        private InventoryReport BuildReportFromUI()
        {
            InventoryReport r = new InventoryReport();
            r.Set("Categoria Ubicacion", cmbCat != null ? cmbCat.Text.Trim() : "");
            r.Set("Area / Ambiente", cmbArea != null ? cmbArea.Text.Trim().ToUpper() : "");
            r.Set("Piso Ubicacion", txtPiso != null ? txtPiso.Text.Trim().ToUpper() : "");
            r.Set("Seguridad Fisica", cmbSeg != null ? cmbSeg.Text.Trim().ToUpper() : "");
            r.Set("Tipo de Equipo", txtTipo != null ? txtTipo.Text.Trim() : "");
            r.Set("Marca", txtMarca != null ? txtMarca.Text.Trim() : "");
            r.Set("Modelo", txtModelo != null ? txtModelo.Text.Trim() : "");
            r.Set("Serie del Equipo", txtSerie != null ? txtSerie.Text.Trim() : "");
            r.Set("Hostname", txtHost != null ? txtHost.Text.Trim() : "");
            r.Set("Dominio / Grupo", txtDom != null ? txtDom.Text.Trim() : "");
            r.Set("Sistema Operativo", txtSO != null ? txtSO.Text.Trim() : "");
            r.Set("Procesador", txtCPU != null ? txtCPU.Text.Trim() : "");
            r.Set("Memoria RAM", txtRAM != null ? txtRAM.Text.Trim() : "");
            r.Set("Almacenamiento", txtDisk != null ? txtDisk.Text.Trim() : "");
            r.Set("Antivirus", secAntivirus);
            r.Set("Absolute", secAbsolute);
            r.Set("HP Insights", secHpInsights);

            r.Users.AddRange(SplitLines(txtUsers != null ? txtUsers.Text : ""));
            foreach (NetAdapterInfo n in activeNets) r.Nets.Add(InventoryReport.CloneNet(n));
            r.Monitors.AddRange(SplitLines(txtMons != null ? txtMons.Text : ""));
            r.Ajustes.AddRange(currentAjustes);

            r.FechaAuditoria = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            r.UsuarioEjecutor = currentUserExec;
            return r;
        }

        private List<string> ReportToLines(InventoryReport r)
        {
            const string SEP = "--------------------------------------------------------";
            List<string> lines = new List<string>();
            lines.Add("========================================================");
            lines.Add("              INVENTARIO DE HARDWARE Y RED              ");
            lines.Add("========================================================");
            for (int i = 0; i < 4; i++)
                lines.Add(RptLine(InventoryReport.FieldKeys[i], r.Get(InventoryReport.FieldKeys[i])));
            lines.Add(SEP);
            for (int i = 4; i < InventoryReport.FieldKeys.Length; i++)
                lines.Add(RptLine(InventoryReport.FieldKeys[i], r.Get(InventoryReport.FieldKeys[i])));
            lines.Add(SEP);

            if (r.Users.Count > 0)
            {
                foreach (string u in r.Users) lines.Add(RptLine("Usuario Equipo", u));
            }
            else
            {
                lines.Add(RptLine("Usuario Equipo", "No se detectaron perfiles de usuario (validar presencialmente)"));
            }

            if (r.Nets.Count > 0)
            {
                foreach (NetAdapterInfo nb in r.Nets)
                {
                    lines.Add(SEP);
                    lines.Add(RptLine("Adaptador Activo", nb.Description));
                    lines.Add(RptLine("Direccion IPv4", nb.IPv4));
                    lines.Add(RptLine("Puerta de Enlace", nb.Gateway));
                    lines.Add(RptLine("Servidores DNS", nb.DNS));
                    lines.Add(RptLine("MAC Address", nb.MAC));
                }
            }
            else
            {
                lines.Add(SEP);
                lines.Add(RptLine("Red Activa", "Sin conexion activa a red (validar cable/Wi-Fi presencialmente)"));
            }

            lines.Add(SEP);
            if (r.Monitors.Count > 0)
            {
                foreach (string m in r.Monitors) lines.Add(RptLine("Monitor", m));
            }
            else
            {
                lines.Add(RptLine("Monitor", "No se detecto monitor o no reporta datos EDID (validar presencialmente)"));
            }

            if (r.Ajustes.Count > 0)
            {
                lines.Add(SEP);
                foreach (KeyValuePair<string, string> aj in r.Ajustes)
                    lines.Add(RptLine("Ajuste Manual", OneLine(aj.Key) + " = " + OneLine(aj.Value)));
            }

            lines.Add("========================================================");
            lines.Add(RptLine("Fecha de Auditoria", r.FechaAuditoria));
            lines.Add(RptLine("Usuario Ejecutor", r.UsuarioEjecutor));
            return lines;
        }

        private List<string> BuildReportLines()
        {
            return ReportToLines(BuildReportFromUI());
        }

        private InventoryReport ParseReport(string[] lines)
        {
            InventoryReport r = new InventoryReport();
            HashSet<string> keys = new HashSet<string>(InventoryReport.FieldKeys, StringComparer.OrdinalIgnoreCase);
            NetAdapterInfo cur = null;

            foreach (string line in lines)
            {
                int idx = line.IndexOf(':');
                if (idx <= 0) continue;
                string k = line.Substring(0, idx).Trim();
                string v = line.Substring(idx + 1).Trim();

                if (string.Equals(k, "Usuario Equipo", StringComparison.OrdinalIgnoreCase))
                {
                    if (v.IndexOf("No se detectaron", StringComparison.OrdinalIgnoreCase) < 0) r.Users.Add(v);
                }
                else if (string.Equals(k, "Adaptador Activo", StringComparison.OrdinalIgnoreCase))
                {
                    cur = new NetAdapterInfo();
                    cur.Description = v; cur.IPv4 = ""; cur.Gateway = ""; cur.DNS = ""; cur.MAC = "";
                    r.Nets.Add(cur);
                }
                else if (string.Equals(k, "Direccion IPv4", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(k, "Puerta de Enlace", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(k, "Servidores DNS", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(k, "MAC Address", StringComparison.OrdinalIgnoreCase))
                {
                    if (cur == null)
                    {
                        cur = new NetAdapterInfo();
                        cur.Description = ""; cur.IPv4 = ""; cur.Gateway = ""; cur.DNS = ""; cur.MAC = "";
                        r.Nets.Add(cur);
                    }
                    if (k.StartsWith("Direccion", StringComparison.OrdinalIgnoreCase)) cur.IPv4 = v;
                    else if (k.StartsWith("Puerta", StringComparison.OrdinalIgnoreCase)) cur.Gateway = v;
                    else if (k.StartsWith("Servidores", StringComparison.OrdinalIgnoreCase)) cur.DNS = v;
                    else cur.MAC = v;
                }
                else if (string.Equals(k, "Monitor", StringComparison.OrdinalIgnoreCase))
                {
                    if (v.IndexOf("No se detecto", StringComparison.OrdinalIgnoreCase) < 0) r.Monitors.Add(v);
                }
                else if (string.Equals(k, "Ajuste Manual", StringComparison.OrdinalIgnoreCase))
                {
                    int eq = v.IndexOf(" = ", StringComparison.Ordinal);
                    if (eq > 0) r.SetAjuste(v.Substring(0, eq).Trim(), v.Substring(eq + 3).Trim());
                    else if (v.EndsWith(" =")) r.SetAjuste(v.Substring(0, v.Length - 2).Trim(), "");
                }
                else if (string.Equals(k, "Fecha de Auditoria", StringComparison.OrdinalIgnoreCase))
                {
                    r.FechaAuditoria = v;
                }
                else if (string.Equals(k, "Usuario Ejecutor", StringComparison.OrdinalIgnoreCase))
                {
                    r.UsuarioEjecutor = v;
                }
                else if (keys.Contains(k) && !r.Fields.ContainsKey(k))
                {
                    r.Set(k, v);
                }
            }
            return r;
        }

        // Carga un reporte en los campos de la pestana 1 (para editarlo manualmente o reflejar lo guardado)
        private void LoadReportIntoUI(InventoryReport r)
        {
            suppressPreview = true;
            try
            {
                int ic = cmbCat.FindStringExact(r.Get("Categoria Ubicacion").ToUpper());
                if (ic >= 0) cmbCat.SelectedIndex = ic;
                cmbArea.Text = r.Get("Area / Ambiente");
                txtPiso.Text = r.Get("Piso Ubicacion");
                cmbSeg.Text = NormalizeSeguridad(r.Get("Seguridad Fisica"));
                // Reportes antiguos guardaban el chasis ("Mini PC", "Notebook"...): se muestra ya como PC / LAPTOP
                txtTipo.Text = NormalizeTipoEquipo(r.Get("Tipo de Equipo"), r.Get("Hostname"));
                txtMarca.Text = r.Get("Marca");
                txtModelo.Text = r.Get("Modelo");
                txtSerie.Text = r.Get("Serie del Equipo");
                txtHost.Text = r.Get("Hostname");
                txtDom.Text = r.Get("Dominio / Grupo");
                txtSO.Text = r.Get("Sistema Operativo");
                txtCPU.Text = r.Get("Procesador");
                txtRAM.Text = r.Get("Memoria RAM");
                txtDisk.Text = r.Get("Almacenamiento");
                secAntivirus = r.Get("Antivirus");
                secAbsolute = r.Get("Absolute");
                secHpInsights = r.Get("HP Insights");
                txtUsers.Text = string.Join(Environment.NewLine, r.Users.ToArray());
                txtMons.Text = string.Join(Environment.NewLine, r.Monitors.ToArray());
                activeNets = new List<NetAdapterInfo>();
                foreach (NetAdapterInfo n in r.Nets) activeNets.Add(InventoryReport.CloneNet(n));
                currentAjustes = new List<KeyValuePair<string, string>>(r.Ajustes);
            }
            finally
            {
                suppressPreview = false;
                UpdatePreview();
            }
        }

        private void UpdatePreview()
        {
            if (suppressPreview || rtbPreview == null) return;
            List<string> lines = BuildReportLines();
            rtbPreview.Text = string.Join(Environment.NewLine, lines.ToArray());
        }

        private void BtnAddArea_Click(object sender, EventArgs e)
        {
            string cod = PromptInput("Registrar Nueva Sigla de \u00C1rea", "Ingresa la ABREVIATURA del hostname (ej. ADM, CAJ, RRHH):", "");
            if (string.IsNullOrWhiteSpace(cod)) return;
            cod = cod.Trim().ToUpper();

            string nom = PromptInput("Nombre Completo del \u00C1rea", "Ingresa el nombre completo del \u00C1REA para [" + cod + "]:", "");
            if (string.IsNullOrWhiteSpace(nom)) return;
            nom = nom.Trim().ToUpper();

            string piso = PromptInput("Piso Habitual", "Ingresa el PISO para [" + nom + "] (ej. 1, 2, S\u00D3TANO):", txtPiso.Text);
            areaMap[cod] = nom;
            if (!string.IsNullOrWhiteSpace(piso))
            {
                pisosMap[cod] = piso.Trim().ToUpper();
                txtPiso.Text = pisosMap[cod];
            }
            SaveConfig();
            RefreshAreaCombo();
            cmbArea.Text = nom;
            UpdatePreview();
        }

        // ===================== Pestana 1: abrir, comparar por campo y guardar =====================

        private class FieldDiff
        {
            public int Kind;      // 0 = campo simple, 1 = usuarios, 2 = monitores, 3 = red (MAC), 4 = ajuste manual
            public string Key;
            public string Label;
            public string Antes;
            public string Ahora;
            public bool UseAntes;
        }

        private void BtnOpenReport_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog dlg = new OpenFileDialog())
            {
                dlg.Title = "Abrir reporte de inventario existente";
                dlg.Filter = "Reportes de inventario (*.txt)|*.txt";
                dlg.InitialDirectory = baseDir;
                if (dlg.ShowDialog(this) != DialogResult.OK) return;

                string[] lines;
                try { lines = File.ReadAllLines(dlg.FileName, Encoding.UTF8); }
                catch (Exception ex)
                {
                    MessageBox.Show("No se pudo leer el archivo:\n" + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (string.Join("\n", lines).IndexOf("INVENTARIO DE HARDWARE Y RED", StringComparison.Ordinal) < 0)
                {
                    MessageBox.Show("El archivo seleccionado no es un reporte de inventario.", "Archivo no v\u00E1lido", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                LoadReportIntoUI(ParseReport(lines));
                lblStatusText.Text = "Reporte abierto para edici\u00F3n: " + RelPath(dlg.FileName) + "  (corrige los campos y presiona GUARDAR para comparar y actualizar)";
            }
        }

        private string RelPath(string fullPath)
        {
            if (fullPath != null && fullPath.StartsWith(baseDir, StringComparison.OrdinalIgnoreCase))
                return fullPath.Substring(baseDir.Length).TrimStart('\\');
            return fullPath;
        }

        private static bool PathsEqual(string a, string b)
        {
            try { return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase); }
            catch { return string.Equals(a, b, StringComparison.OrdinalIgnoreCase); }
        }

        private static string SafeFolderName(string s)
        {
            return Regex.Replace((s ?? "").Trim().ToUpper(), @"[\\/:*?""<>|]", "-").Trim();
        }

        private string GetReportPath(InventoryReport r)
        {
            string cat = SafeFolderName(r.Get("Categoria Ubicacion"));
            if (cat.Length == 0) cat = "ADMINISTRATIVOS";
            string are = SafeFolderName(r.Get("Area / Ambiente"));
            if (are.Length == 0) are = "GENERAL";
            string nombre = string.Format("{0}.{1}.txt", r.Get("Hostname").Trim(), r.Get("Dominio / Grupo").Trim());
            return Path.Combine(Path.Combine(Path.Combine(baseDir, cat), are), nombre);
        }

        private void WriteReportFile(string path, InventoryReport r)
        {
            string dir = Path.GetDirectoryName(path);
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
            File.WriteAllLines(path, ReportToLines(r).ToArray(), Encoding.UTF8);
            lastSavedReportPath = path;
        }

        // Busca el reporte vigente del equipo en TODAS las carpetas de inventario (no solo en la carpeta actual)
        private FileInfo FindExistingReport(string host, string preferredPath, out int count)
        {
            List<FileInfo> matches = new List<FileInfo>();
            foreach (FileInfo fi in GetInventoryTxtFiles())
            {
                if (!string.Equals(fi.Name.Split('.')[0], host, StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    if (File.ReadAllText(fi.FullName, Encoding.UTF8).IndexOf("INVENTARIO DE HARDWARE Y RED", StringComparison.Ordinal) >= 0)
                        matches.Add(fi);
                }
                catch { }
            }
            count = matches.Count;
            if (matches.Count == 0) return null;
            foreach (FileInfo m in matches)
            {
                if (PathsEqual(m.FullName, preferredPath)) return m;
            }
            return matches.OrderByDescending(x => x.LastWriteTime).First();
        }

        // Compara por campo. La IP, puerta de enlace y DNS NO se comparan (cambian por DHCP); la MAC si.
        private List<FieldDiff> ComputeReportDiffs(InventoryReport antes, InventoryReport ahora)
        {
            List<FieldDiff> list = new List<FieldDiff>();
            foreach (string key in InventoryReport.FieldKeys)
            {
                string a = antes.Get(key).Trim();
                string b = ahora.Get(key).Trim();
                if (!string.Equals(a, b, StringComparison.Ordinal))
                    list.Add(NewDiff(0, key, key, a, b, false));
            }

            string ua = string.Join(" | ", antes.Users.ToArray());
            string ub = string.Join(" | ", ahora.Users.ToArray());
            if (!string.Equals(ua, ub, StringComparison.Ordinal))
                list.Add(NewDiff(1, "Usuario Equipo", "Usuarios del equipo", ua, ub, false));

            string ma = string.Join(" | ", antes.Monitors.ToArray());
            string mb = string.Join(" | ", ahora.Monitors.ToArray());
            if (!string.Equals(ma, mb, StringComparison.Ordinal))
                list.Add(NewDiff(2, "Monitor", "Monitores", ma, mb, false));

            string na = string.Join(", ", antes.Nets.Select(n => n.MAC ?? "").ToArray());
            string nb = string.Join(", ", ahora.Nets.Select(n => n.MAC ?? "").ToArray());
            if (!string.Equals(na, nb, StringComparison.Ordinal))
                list.Add(NewDiff(3, "MAC Address", "MAC Address (red)", na, nb, false));

            List<string> cols = new List<string>();
            foreach (KeyValuePair<string, string> kv in antes.Ajustes)
                if (!cols.Contains(kv.Key, StringComparer.OrdinalIgnoreCase)) cols.Add(kv.Key);
            foreach (KeyValuePair<string, string> kv in ahora.Ajustes)
                if (!cols.Contains(kv.Key, StringComparer.OrdinalIgnoreCase)) cols.Add(kv.Key);
            foreach (string col in cols)
            {
                string oa = antes.GetAjuste(col);
                string ob = ahora.GetAjuste(col);
                if (string.Equals(oa, ob, StringComparison.Ordinal)) continue;
                // Por defecto se CONSERVA la correccion manual anterior; el tecnico decide si la descarta
                list.Add(NewDiff(4, col, "Ajuste manual: " + col,
                    oa ?? "(sin ajuste)", ob ?? "(sin ajuste: usar dato detectado)", oa != null));
            }
            return list;
        }

        private static FieldDiff NewDiff(int kind, string key, string label, string antes, string ahora, bool useAntes)
        {
            FieldDiff d = new FieldDiff();
            d.Kind = kind; d.Key = key; d.Label = label; d.Antes = antes; d.Ahora = ahora; d.UseAntes = useAntes;
            return d;
        }

        private InventoryReport MergeReport(InventoryReport antes, InventoryReport ahora, List<FieldDiff> diffs)
        {
            InventoryReport m = ahora.Clone();
            foreach (FieldDiff d in diffs)
            {
                if (!d.UseAntes) continue;
                if (d.Kind == 0) m.Set(d.Key, antes.Get(d.Key));
                else if (d.Kind == 1) m.Users = new List<string>(antes.Users);
                else if (d.Kind == 2) m.Monitors = new List<string>(antes.Monitors);
                else if (d.Kind == 3)
                {
                    m.Nets = new List<NetAdapterInfo>();
                    foreach (NetAdapterInfo n in antes.Nets) m.Nets.Add(InventoryReport.CloneNet(n));
                }
                else if (d.Kind == 4) m.SetAjuste(d.Key, antes.GetAjuste(d.Key));
            }
            return m;
        }

        private void BtnSaveTxt_Click(object sender, EventArgs e)
        {
            InventoryReport nuevo = BuildReportFromUI();
            string host = nuevo.Get("Hostname").Trim();
            if (host.Length == 0)
            {
                MessageBox.Show("El campo Hostname est\u00E1 vac\u00EDo. Compl\u00E9talo antes de guardar.", "Falta Hostname", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string destino = GetReportPath(nuevo);
            int cantidad;
            FileInfo previo = FindExistingReport(host, destino, out cantidad);
            if (previo == null)
            {
                WriteReportFile(destino, nuevo);
                MessageBox.Show("Reporte guardado en subcarpeta:\n" + destino, "Reporte Guardado", MessageBoxButtons.OK, MessageBoxIcon.Information);
                UpdateTxtCounterBadge();
                OfferDriveUploadAfterSave();
                return;
            }

            InventoryReport anterior = ParseReport(File.ReadAllLines(previo.FullName, Encoding.UTF8));
            List<FieldDiff> diffs = ComputeReportDiffs(anterior, nuevo);
            if (diffs.Count == 0)
            {
                DialogResult dr = MessageBox.Show(
                    string.Format("El reporte de {0} ya existe en {1} y NO presenta cambios.\n\n\u00BFDeseas actualizar la fecha de auditor\u00EDa de todas formas?", host, RelPath(previo.FullName)),
                    "Sin Cambios Detectados", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                if (dr == DialogResult.Yes)
                {
                    WriteReportFile(previo.FullName, nuevo);
                    lblStatusText.Text = "Fecha de auditor\u00EDa actualizada en " + previo.FullName;
                    OfferDriveUploadAfterSave();
                }
                return;
            }

            int op = ShowFieldDiffDialog(host, previo, cantidad, anterior, destino, diffs);
            if (op != 1 && op != 2) return;

            InventoryReport final;
            string resumen;
            try
            {
                resumen = ApplyReportSave(previo, anterior, nuevo, diffs, op, out final);
            }
            catch (Exception ex)
            {
                MessageBox.Show("No se pudo guardar el reporte:\n" + ex.Message, "Error al Guardar", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            LoadReportIntoUI(final);
            UpdateTxtCounterBadge();
            MessageBox.Show(resumen, "Reporte Actualizado", MessageBoxButtons.OK, MessageBoxIcon.Information);
            OfferDriveUploadAfterSave();
        }

        // op: 1 = archivar el reporte ANTERIOR con fecha y dejar el nuevo como vigente; 2 = sin historial
        private string ApplyReportSave(FileInfo previo, InventoryReport anterior, InventoryReport nuevo, List<FieldDiff> diffs, int op, out InventoryReport final)
        {
            final = MergeReport(anterior, nuevo, diffs);
            string destino = GetReportPath(final);
            StringBuilder sb = new StringBuilder();

            if (op == 1)
            {
                string dir = Path.GetDirectoryName(destino);
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                string hist = Path.Combine(dir, string.Format("{0}_{1}.txt",
                    Path.GetFileNameWithoutExtension(previo.Name), DateTime.Now.ToString("yyyyMMdd_HHmmss")));
                File.Copy(previo.FullName, hist, true);
                sb.Append("Reporte anterior archivado como:\n" + hist + "\n\n");
            }

            WriteReportFile(destino, final);
            sb.Append("Reporte vigente actualizado:\n" + destino);

            if (!PathsEqual(previo.FullName, destino))
            {
                try
                {
                    File.Delete(previo.FullName);
                    sb.Append("\n\nSe movi\u00F3 desde:\n" + previo.FullName);
                }
                catch (Exception ex)
                {
                    sb.Append("\n\nNo se pudo eliminar el reporte anterior (" + ex.Message + "):\n" + previo.FullName);
                }
            }
            return sb.ToString();
        }

        private static DataGridView NewCompareGrid()
        {
            DataGridView g = new DataGridView();
            g.Dock = DockStyle.Fill;
            g.AllowUserToAddRows = false;
            g.AllowUserToDeleteRows = false;
            g.AllowUserToResizeRows = false;
            g.RowHeadersVisible = false;
            g.BackgroundColor = Color.White;
            g.BorderStyle = BorderStyle.FixedSingle;
            g.SelectionMode = DataGridViewSelectionMode.CellSelect;
            g.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            g.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells;
            g.DefaultCellStyle.WrapMode = DataGridViewTriState.True;
            g.EditMode = DataGridViewEditMode.EditOnEnter;
            g.EnableHeadersVisualStyles = false;
            g.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(30, 41, 59);
            g.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            g.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 9F);
            return g;
        }

        private static DataGridViewTextBoxColumn TextCol(string header, float weight)
        {
            DataGridViewTextBoxColumn c = new DataGridViewTextBoxColumn();
            c.HeaderText = header;
            c.ReadOnly = true;
            c.FillWeight = weight;
            c.SortMode = DataGridViewColumnSortMode.NotSortable;
            return c;
        }

        private static DataGridViewComboBoxColumn ChoiceCol(string header, float weight, string[] items)
        {
            DataGridViewComboBoxColumn c = new DataGridViewComboBoxColumn();
            c.HeaderText = header;
            c.FillWeight = weight;
            c.FlatStyle = FlatStyle.Flat;
            c.SortMode = DataGridViewColumnSortMode.NotSortable;
            foreach (string it in items) c.Items.Add(it);
            return c;
        }

        private static Button DialogButton(string text, int width, Color back, Color fore)
        {
            Button b = new Button();
            b.Text = text;
            b.Size = new Size(width, 34);
            b.BackColor = back;
            b.ForeColor = fore;
            b.FlatStyle = FlatStyle.Flat;
            b.Margin = new Padding(6, 6, 0, 0);
            return b;
        }

        // Devuelve 1 = guardar y archivar anterior, 2 = guardar sin historial, 3 = cancelar. Marca UseAntes en cada diferencia.
        private int ShowFieldDiffDialog(string host, FileInfo previo, int cantidad, InventoryReport anterior, string destino, List<FieldDiff> diffs)
        {
            Form f = new Form();
            f.Text = "Auditor\u00EDa de Diferencias - " + host;
            f.Size = new Size(1000, 620);
            f.MinimumSize = new Size(760, 420);
            f.StartPosition = FormStartPosition.CenterParent;
            f.MinimizeBox = false;
            f.ShowInTaskbar = false;
            f.Font = new Font("Segoe UI", 9F);

            string info = string.Format(
                "Se detectaron {0} cambio(s) respecto al reporte anterior de {1}. En la columna \"Usar\" elige qu\u00E9 valor se guarda. (La IP, puerta de enlace y DNS no se comparan.)\nReporte anterior: {2}   |   Auditado: {3}",
                diffs.Count, host, RelPath(previo.FullName), anterior.FechaAuditoria);
            if (cantidad > 1)
                info += string.Format("   |   Hay {0} reportes de este equipo; se compara con el vigente.", cantidad);
            if (!string.Equals(Path.GetDirectoryName(previo.FullName), Path.GetDirectoryName(destino), StringComparison.OrdinalIgnoreCase))
                info += "\nEl reporte anterior est\u00E1 en otra carpeta: si usas la Categor\u00EDa/\u00C1rea de \"Ahora\", el reporte se mover\u00E1 a la nueva ubicaci\u00F3n.";

            Label lbl = new Label();
            lbl.Text = info;
            lbl.Dock = DockStyle.Top;
            lbl.Height = 64;
            lbl.Padding = new Padding(10, 8, 10, 0);

            Panel pnlGrid = new Panel();
            pnlGrid.Dock = DockStyle.Fill;
            pnlGrid.Padding = new Padding(10, 0, 10, 0);

            FlowLayoutPanel bar = new FlowLayoutPanel();
            bar.Dock = DockStyle.Top;
            bar.Height = 44;
            bar.FlowDirection = FlowDirection.LeftToRight;
            Button bAllNew = DialogButton("Usar todo lo nuevo", 170, Color.FromArgb(224, 242, 254), Color.Black);
            Button bAllOld = DialogButton("Mantener todo lo anterior", 190, Color.FromArgb(226, 232, 240), Color.Black);
            Label hint = new Label();
            hint.Text = "Filas amarillas = correcciones manuales (Ajuste Manual): por defecto se conservan.";
            hint.AutoSize = true;
            hint.Margin = new Padding(12, 15, 0, 0);
            bar.Controls.Add(bAllNew);
            bar.Controls.Add(bAllOld);
            bar.Controls.Add(hint);

            DataGridView g = NewCompareGrid();
            g.Columns.Add(TextCol("Campo", 22));
            g.Columns.Add(TextCol("Antes (reporte guardado)", 34));
            g.Columns.Add(TextCol("Ahora (nuevo)", 34));
            g.Columns.Add(ChoiceCol("Usar", 12, new string[] { "Ahora", "Antes" }));
            foreach (FieldDiff d in diffs)
            {
                int ri = g.Rows.Add(d.Label, d.Antes, d.Ahora, d.UseAntes ? "Antes" : "Ahora");
                if (d.Kind == 4) g.Rows[ri].DefaultCellStyle.BackColor = Color.FromArgb(254, 249, 195);
            }
            bAllNew.Click += delegate { foreach (DataGridViewRow gr in g.Rows) gr.Cells[3].Value = "Ahora"; };
            bAllOld.Click += delegate { foreach (DataGridViewRow gr in g.Rows) gr.Cells[3].Value = "Antes"; };

            pnlGrid.Controls.Add(g);
            pnlGrid.Controls.Add(bar);

            FlowLayoutPanel bottom = new FlowLayoutPanel();
            bottom.Dock = DockStyle.Bottom;
            bottom.Height = 54;
            bottom.FlowDirection = FlowDirection.RightToLeft;
            bottom.Padding = new Padding(0, 4, 10, 0);
            Button b3 = DialogButton("Cancelar", 120, Color.FromArgb(241, 245, 249), Color.Black);
            Button b2 = DialogButton("Guardar sin historial", 190, Color.FromArgb(21, 128, 61), Color.White);
            Button b1 = DialogButton("Guardar y archivar el reporte anterior", 290, Color.FromArgb(37, 99, 235), Color.White);
            bottom.Controls.Add(b3);
            bottom.Controls.Add(b2);
            bottom.Controls.Add(b1);

            f.Controls.Add(pnlGrid);
            f.Controls.Add(bottom);
            f.Controls.Add(lbl);

            int choice = 3;
            EventHandler accept = delegate(object s, EventArgs ev)
            {
                g.EndEdit();
                for (int i = 0; i < diffs.Count; i++)
                    diffs[i].UseAntes = string.Equals(Convert.ToString(g.Rows[i].Cells[3].Value), "Antes", StringComparison.Ordinal);
                choice = (s == b1) ? 1 : 2;
                f.Close();
            };
            b1.Click += accept;
            b2.Click += accept;
            b3.Click += delegate { choice = 3; f.Close(); };

            f.ShowDialog(this);
            return choice;
        }

        private void LoadTxtFilesIntoTable()
        {
            if (!ConfirmSaveOrDiscardGridChanges()) return;

            tecnicosResponsables = txtTec.Text.Trim().ToUpper();
            orgWienerGuardada = txtOrgW.Text.Trim().ToUpper();
            SaveConfig();

            tableTodos = new DataTable("INVENTARIO");
            foreach (string col in headersAdm) tableTodos.Columns.Add(col);
            tableTodos.Columns.Add("_CATEGORIA_INTERNA");
            tableTodos.Columns.Add("_ARCHIVO");
            calcByFile = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            loadedByFile = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            hpAgentByFile = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            List<FileInfo> candidateFiles = GetInventoryTxtFiles();
            List<FileInfo> validFiles = new List<FileInfo>();
            foreach (FileInfo fi in candidateFiles)
            {
                try
                {
                    string content = File.ReadAllText(fi.FullName, Encoding.UTF8);
                    if (content.Contains("INVENTARIO DE HARDWARE Y RED"))
                        validFiles.Add(fi);
                }
                catch { }
            }

            var grouped = validFiles
                .OrderByDescending(f => f.LastWriteTime)
                .GroupBy(f => f.Name.Split('.')[0].ToUpper())
                .Select(g => g.First())
                .OrderBy(f => f.FullName)
                .ToList();

            foreach (FileInfo file in grouped)
            {
                string[] lines = File.ReadAllLines(file.FullName, Encoding.UTF8);
                Dictionary<string, string> data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                List<string> users = new List<string>();
                List<string> mons = new List<string>();
                List<string> macs = new List<string>();

                foreach (string line in lines)
                {
                    int idx = line.IndexOf(':');
                    if (idx <= 0) continue;
                    string k = line.Substring(0, idx).Trim();
                    string v = line.Substring(idx + 1).Trim();

                    if (string.Equals(k, "Usuario Equipo", StringComparison.OrdinalIgnoreCase))
                    {
                        if (v.IndexOf("No se detectaron", StringComparison.OrdinalIgnoreCase) < 0) users.Add(v);
                    }
                    else if (string.Equals(k, "Monitor", StringComparison.OrdinalIgnoreCase))
                    {
                        if (v.IndexOf("No se detecto", StringComparison.OrdinalIgnoreCase) < 0) mons.Add(v);
                    }
                    else if (string.Equals(k, "MAC Address", StringComparison.OrdinalIgnoreCase))
                    {
                        if (v.IndexOf("No disponible", StringComparison.OrdinalIgnoreCase) < 0) macs.Add(v);
                    }
                    else if (!data.ContainsKey(k))
                    {
                        data[k] = v;
                    }
                }

                string hostName = data.ContainsKey("Hostname") ? data["Hostname"].ToUpper() : file.Name.Split('.')[0].ToUpper();

                string orgActual = "IDAC";
                if (cmbInst.SelectedIndex == 1) orgActual = "IDAC";
                else if (cmbInst.SelectedIndex == 2) orgActual = orgWienerGuardada;
                else orgActual = hostName.StartsWith("W", StringComparison.OrdinalIgnoreCase) ? orgWienerGuardada : "IDAC";

                string tipoRaw = data.ContainsKey("Tipo de Equipo") ? data["Tipo de Equipo"] : "";
                string tipo = NormalizeTipoEquipo(tipoRaw, hostName);

                string pestanaDestino = data.ContainsKey("Categoria Ubicacion") ? data["Categoria Ubicacion"].ToUpper() : "ADMINISTRATIVOS";
                string piso = data.ContainsKey("Piso Ubicacion") ? data["Piso Ubicacion"] : "";
                string area = data.ContainsKey("Area / Ambiente") ? data["Area / Ambiente"] : "";
                string remachado = NormalizeSeguridad(data.ContainsKey("Seguridad Fisica") ? data["Seguridad Fisica"] : "");
                if (string.Equals(remachado, "NINGUNO", StringComparison.OrdinalIgnoreCase)) remachado = "";

                string aulaLabAdm = "ADMINISTRATIVO";
                Match mAu = Regex.Match(hostName, @"^[A-Z]+\d+(?:PC|LP)AU(\d{3})\d*");
                Match mLb = Regex.Match(hostName, @"^[A-Z]+\d+(?:PC|LP)LB(\d{3})\d*");
                Match mAd = Regex.Match(hostName, @"^[A-Z]+\d+(?:PC|LP)AD([A-Z]+)\d*");

                if (mAu.Success)
                {
                    string numAula = mAu.Groups[1].Value;
                    pestanaDestino = "AULAS";
                    if (string.IsNullOrEmpty(piso)) piso = numAula.Substring(0, 1);
                    if (string.IsNullOrEmpty(area)) area = "AULA " + numAula;
                    aulaLabAdm = area;
                    if (string.IsNullOrEmpty(remachado) && tipo == "PC") remachado = "SIN REMACHE/SIN CADENA";
                }
                else if (mLb.Success)
                {
                    string numLab = mLb.Groups[1].Value;
                    pestanaDestino = "LABORATORIO";
                    if (string.IsNullOrEmpty(piso)) piso = numLab.Substring(0, 1);
                    if (string.IsNullOrEmpty(area)) area = "LABORATORIO DE COMPUTO " + numLab;
                    aulaLabAdm = area;
                    if (string.IsNullOrEmpty(remachado) && tipo == "PC") remachado = "CON REMACHE/SIN CADENA";
                }
                else if (mAd.Success)
                {
                    string codArea = mAd.Groups[1].Value.ToUpper();
                    pestanaDestino = "ADMINISTRATIVOS";
                    aulaLabAdm = "ADMINISTRATIVO";
                    if (string.IsNullOrEmpty(area))
                    {
                        if (!areaMap.ContainsKey(codArea))
                        {
                            string nuevoA = PromptInput("Abreviatura de \u00C1rea Nueva",
                                string.Format("Se detect\u00F3 la abreviatura [{0}] en el equipo {1}.\nIngresa el nombre del \u00C1REA:", codArea, hostName), "");
                            if (!string.IsNullOrWhiteSpace(nuevoA))
                            {
                                areaMap[codArea] = nuevoA.Trim().ToUpper();
                                SaveConfig();
                                RefreshAreaCombo();
                            }
                        }
                        area = areaMap.ContainsKey(codArea) ? areaMap[codArea] : codArea;
                    }
                    if (string.IsNullOrEmpty(piso) && pisosMap.ContainsKey(codArea)) piso = pisosMap[codArea];
                    if (string.IsNullOrEmpty(remachado) && tipo == "LAPTOP") remachado = "CADENA DE SEGURIDAD";
                }
                else
                {
                    aulaLabAdm = pestanaDestino == "ADMINISTRATIVOS" ? "ADMINISTRATIVO" : area;
                }

                string marcaRaw = data.ContainsKey("Marca") ? data["Marca"].ToUpper() : "";
                string marca = marcaRaw;
                if (Regex.IsMatch(marcaRaw, @"HP|HEWLETT")) marca = "HP";
                else if (marcaRaw.Contains("LENOVO")) marca = "LENOVO";
                else if (marcaRaw.Contains("DELL")) marca = "DELL";

                string modelo = CleanModeloExcel(data.ContainsKey("Modelo") ? data["Modelo"] : "", marca);

                string serie = data.ContainsKey("Serie del Equipo")
                    ? Regex.Replace(data["Serie del Equipo"], @"\s*\(Serie Placa Base\)", "").Trim()
                    : "";
                string cpu = data.ContainsKey("Procesador") ? data["Procesador"] : "";

                string ramRaw = data.ContainsKey("Memoria RAM") ? data["Memoria RAM"] : "";
                Match mRam = Regex.Match(ramRaw, @"^(\d+(?:\.\d+)?)\s*GB");
                string ram = mRam.Success ? Math.Round(double.Parse(mRam.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture)) + " GB" : ramRaw;

                string diskRaw = data.ContainsKey("Almacenamiento") ? data["Almacenamiento"] : "";
                List<string> diskFormatted = new List<string>();
                foreach (string part in diskRaw.Split(new string[] { " / " }, StringSplitOptions.RemoveEmptyEntries))
                {
                    Match mD = Regex.Match(part, @"\((\d+)\s*GB\)");
                    if (mD.Success)
                    {
                        int gb = int.Parse(mD.Groups[1].Value);
                        if (gb >= 440 && gb <= 505) diskFormatted.Add("500 GB");
                        else if (gb >= 506 && gb <= 530) diskFormatted.Add("512 GB");
                        else if (gb >= 900 && gb <= 1050) diskFormatted.Add("1 TB");
                        else if (gb >= 220 && gb <= 265) diskFormatted.Add("256 GB");
                        else diskFormatted.Add(gb + " GB");
                    }
                }
                string discoDuro = diskFormatted.Count > 0 ? string.Join(" / ", diskFormatted.ToArray()) : diskRaw;

                string macPrincipal = macs.Count > 0 ? macs[0].Replace('-', ':').ToUpper() : "";

                string monModelo = "";
                string monSerie = "";
                if (tipo == "PC" && mons.Count > 0)
                {
                    string m0 = mons[0];
                    string mMarca = Regex.Match(m0, @"Marca:\s*([^|]+)").Groups[1].Value.Trim();
                    string mMod = Regex.Match(m0, @"Modelo:\s*([^|]+)").Groups[1].Value.Trim();
                    string mSer = Regex.Match(m0, @"Serie:\s*(.+)$").Groups[1].Value.Trim();
                    if (!string.IsNullOrEmpty(mMod) && mMod.IndexOf("validar presencialmente", StringComparison.OrdinalIgnoreCase) < 0)
                        monModelo = (mMarca == "HP" && !mMod.StartsWith("HP", StringComparison.OrdinalIgnoreCase)) ? "HP " + mMod : mMod;
                    else
                        monModelo = mMod;
                    monSerie = mSer;
                }
                else if (tipo == "LAPTOP")
                {
                    monModelo = "N/A";
                    monSerie = "N/A";
                }

                string fechaInv = DateTime.Now.ToString("yyyy-MM-dd");
                if (data.ContainsKey("Fecha de Auditoria") && data["Fecha de Auditoria"].Length >= 10)
                    fechaInv = data["Fecha de Auditoria"].Substring(0, 10);

                string usuariosFinal;
                string correosFinal;
                BuildUsuariosExcel(users, pestanaDestino, out usuariosFinal, out correosFinal);

                string agenteHp = data.ContainsKey("HP Insights") ? data["HP Insights"] : "";
                hpAgentByFile[file.FullName] = agenteHp;
                string hpInsights = CalcHpInsights(marca, agenteHp);
                string antivirusCol = CalcAntivirusCol(data.ContainsKey("Antivirus") ? data["Antivirus"] : "");
                string absoluteCol = CalcAgentCol(data.ContainsKey("Absolute") ? data["Absolute"] : "");
                string obs = "NINGUNA";
                if (string.Join(" ", lines).IndexOf("validar presencialmente", StringComparison.OrdinalIgnoreCase) >= 0)
                    obs = obs == "NINGUNA" ? "VALIDAR DATOS PRESENCIALMENTE" : obs + " / VALIDAR DATOS PRESENCIALMENTE";

                DataRow row = tableTodos.NewRow();
                object[] vals = new object[] {
                    tipo, piso, "OPERATIVO", marca, modelo, serie, cpu, ram, discoDuro,
                    macPrincipal, hostName, monModelo, monSerie, area, remachado, aulaLabAdm,
                    fechaInv, orgActual, antivirusCol, usuariosFinal, correosFinal, absoluteCol, hpInsights,
                    "", "", tecnicosResponsables, obs, pestanaDestino, file.FullName
                };

                // Valores calculados desde el escaneo (sin correcciones manuales)
                string[] calc = new string[headersAdm.Length];
                for (int ci = 0; ci < headersAdm.Length; ci++) calc[ci] = Convert.ToString(vals[ci]);

                // Aplicar las correcciones manuales guardadas en el .txt (lineas "Ajuste Manual")
                bool ajMarca = false;
                bool ajHp = false;
                foreach (KeyValuePair<string, string> aj in ParseReport(lines).Ajustes)
                {
                    int ci = ColIdx(aj.Key);
                    if (ci < 0) continue;
                    vals[ci] = aj.Value;
                    if (ci == ColIdx("MARCA")) ajMarca = true;
                    if (ci == ColIdx("HP INSIGHTS")) ajHp = true;
                }
                if (ajMarca && !ajHp)
                    vals[ColIdx("HP INSIGHTS")] = CalcHpInsights(Convert.ToString(vals[ColIdx("MARCA")]), agenteHp);

                string[] loaded = new string[headersAdm.Length];
                for (int ci = 0; ci < headersAdm.Length; ci++) loaded[ci] = Convert.ToString(vals[ci]);
                calcByFile[file.FullName] = calc;
                loadedByFile[file.FullName] = loaded;

                row.ItemArray = vals;
                tableTodos.Rows.Add(row);
            }

            // Se engancha despues de la carga: solo reacciona a ediciones posteriores de MARCA
            tableTodos.ColumnChanged += TableTodos_ColumnChanged;

            ApplyGridFilter();
            UpdateTxtCounterBadge();
        }

        // MODELO para el Excel: solo el modelo comercial. Ej. "HP Pro Mini 400 G9 Desktop PC (SBKPFV3)" -> "Pro Mini 400 G9",
        // "HP ProBook 450 15.6 inch G10 Notebook PC (SBKPFV3)" -> "ProBook 450 G10". En Lenovo el nombre comercial
        // viene entre parentesis (Win32_ComputerSystemProduct.Version) y es el que se usa.
        private static string CleanModeloExcel(string modelo, string marca)
        {
            string m = (modelo ?? "").Trim();
            if (m.IndexOf("validar presencialmente", StringComparison.OrdinalIgnoreCase) >= 0) return m;
            Match mPar = Regex.Match(m, @"\(([^)]+)\)\s*$");
            if (mPar.Success && string.Equals(marca, "LENOVO", StringComparison.OrdinalIgnoreCase))
                m = mPar.Groups[1].Value.Trim();
            else
                m = Regex.Replace(m, @"\s*\([^)]*\)\s*$", "");
            m = Regex.Replace(m, @"^(HP|Hewlett[- ]Packard|Lenovo|Dell( Inc\.)?)\s+", "", RegexOptions.IgnoreCase);
            m = Regex.Replace(m, @"\s+(Desktop\s+Mini|Small\s+Form\s+Factor|Micro\s*tower|Tower|Desktop|Notebook|Laptop|All[- ]in[- ]One|Mobile\s+Workstation|Workstation)(\s+PC)?$", "", RegexOptions.IgnoreCase);
            m = Regex.Replace(m, @"\s+\d+(\.\d+)?\s*(-?inch|in|"")(?=\s|$)", "", RegexOptions.IgnoreCase);
            return Regex.Replace(m, @"\s{2,}", " ").Trim();
        }

        // Valores de REMACHADO / CADENA uniformes (decision del usuario). Convierte tambien los de reportes antiguos.
        private static string NormalizeSeguridad(string s)
        {
            string v = Regex.Replace((s ?? "").Trim().ToUpperInvariant(), @"\s*/\s*", "/");
            if (v == "REMACHE Y CADENA" || v == "REMACHE/CADENA" || v == "CON REMACHE/CON CADENA") return "CON REMACHE/CON CADENA";
            if (v == "REMACHE/SIN CADENA" || v == "CON REMACHE/SIN CADENA") return "CON REMACHE/SIN CADENA";
            if (v == "SIN REMACHE/SIN CADENA") return "SIN REMACHE/SIN CADENA";
            if (v == "SIN REMACHE/CADENA" || v == "SIN REMACHE/CON CADENA") return "SIN REMACHE/CON CADENA";
            return (s ?? "").Trim();
        }

        private static string SinTildes(string s)
        {
            string d = (s ?? "").Normalize(NormalizationForm.FormD);
            StringBuilder sb = new StringBuilder();
            foreach (char c in d)
            {
                if (System.Globalization.CharUnicodeInfo.GetUnicodeCategory(c) != System.Globalization.UnicodeCategory.NonSpacingMark)
                    sb.Append(c);
            }
            return sb.ToString();
        }

        // NOMBRE Y APELLIDO / CORREO para el Excel a partir de las lineas "Usuario Equipo" del .txt:
        // - Se ignoran las cuentas LOCALES de soporte (nombre o cuenta con "soporte") y la cuenta soporte.ti.
        // - Cuentas genericas: "doc..." = DOCENTE y "alu..." = ALUMNO (doccarrion, alucarrion y equivalentes UPNW), sin correo.
        // - CORREO: solo los correos de usuarios reales; "N/A" si todos son DOCENTE / ALUMNO.
        // - Sin usuarios: AULAS / LABORATORIO = DOCENTE con N/A; ADMINISTRATIVOS = vacio (se completa a mano).
        private static void BuildUsuariosExcel(List<string> users, string categoria, out string nombres, out string correos)
        {
            List<string> nombresArr = new List<string>();
            List<string> correosArr = new List<string>();
            bool hayGenerico = false;
            foreach (string u in users)
            {
                string uAcc = Regex.Match(u, @"Usuario:\s*([^\[|]+)").Groups[1].Value.Trim();
                string uName = Regex.Match(u, @"Nombre:\s*([^|]+)").Groups[1].Value.Trim();
                string uMail = Regex.Match(u, @"Correo:\s*(.+)$").Groups[1].Value.Trim();
                bool local = u.IndexOf("[Local]", StringComparison.OrdinalIgnoreCase) >= 0;
                string uShort = uAcc.Contains("\\") ? uAcc.Substring(uAcc.IndexOf('\\') + 1) : uAcc;
                if (uName.IndexOf("Sin nombre registrado", StringComparison.OrdinalIgnoreCase) >= 0) uName = "";

                string cuenta = SinTildes(uShort).ToLowerInvariant();
                if (cuenta == "soporte.ti") continue;
                if (local && (cuenta.Contains("soporte") || SinTildes(uName).ToLowerInvariant().Contains("soporte"))) continue;

                string generico = null;
                if (cuenta.StartsWith("doc")) generico = "DOCENTE";
                else if (cuenta.StartsWith("alu")) generico = "ALUMNO";
                if (generico != null)
                {
                    hayGenerico = true;
                    if (!nombresArr.Contains(generico)) nombresArr.Add(generico);
                    continue;
                }

                string nom = uName.Length > 0 ? uName.ToUpper() : uShort.ToUpper();
                if (nom.Length > 0 && !nombresArr.Contains(nom)) nombresArr.Add(nom);
                if (uMail.Length > 0 && uMail.IndexOf("Sin correo registrado", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    string mail = uMail.ToLower();
                    if (!correosArr.Contains(mail)) correosArr.Add(mail);
                }
            }

            if (nombresArr.Count == 0 && (categoria == "AULAS" || categoria == "LABORATORIO"))
            {
                nombresArr.Add("DOCENTE");
                hayGenerico = true;
            }
            nombres = string.Join("/", nombresArr.ToArray());
            if (correosArr.Count > 0) correos = string.Join("/", correosArr.ToArray());
            else correos = hayGenerico ? "N/A" : "";
        }

        // Regla de negocio: otras marcas = "NO"; en equipos HP depende del agente HP Insights detectado
        // ("SI" / "NO", o "NO VERIFICADO" si el reporte no tiene deteccion o es una fila manual).
        private static string CalcHpInsights(string marca, string agenteDetectado)
        {
            string m = (marca ?? "").Trim().ToUpperInvariant();
            bool esHp = Regex.IsMatch(m, @"\bHP\b") || m.Contains("HEWLETT");
            if (!esHp) return "NO";
            return CalcAgentCol(agenteDetectado);
        }

        private string HpAgentForRow(DataRow row)
        {
            string path = Convert.ToString(row["_ARCHIVO"]);
            string ag;
            if (!string.IsNullOrEmpty(path) && hpAgentByFile.TryGetValue(path, out ag)) return ag;
            return "";
        }

        // Recalcula HP INSIGHTS cuando se edita la MARCA de cualquier fila (manual o cargada desde .txt)
        private void TableTodos_ColumnChanged(object sender, DataColumnChangeEventArgs e)
        {
            if (e.Column == null || e.Column.ColumnName != "MARCA") return;
            string nuevo = CalcHpInsights(e.ProposedValue != null ? e.ProposedValue.ToString() : "", HpAgentForRow(e.Row));
            if (!string.Equals(Convert.ToString(e.Row["HP INSIGHTS"]), nuevo, StringComparison.Ordinal))
                e.Row["HP INSIGHTS"] = nuevo;
            if (grid != null) grid.Invalidate();
        }

        private void ApplyGridFilter()
        {
            if (tableTodos == null) return;
            DataView dv = new DataView(tableTodos);
            string filtro = cmbFiltro.Text;
            if (filtro == "ADMINISTRATIVOS" || filtro == "AULAS" || filtro == "LABORATORIO")
                dv.RowFilter = string.Format("_CATEGORIA_INTERNA = '{0}'", filtro);
            else
                dv.RowFilter = "";

            grid.DataSource = dv;
            if (grid.Columns["_CATEGORIA_INTERNA"] != null)
                grid.Columns["_CATEGORIA_INTERNA"].Visible = false;
            if (grid.Columns["_ARCHIVO"] != null)
                grid.Columns["_ARCHIVO"].Visible = false;

            if (grid.Columns["OBSERVACI\u00D3N"] != null)
                grid.Columns["OBSERVACI\u00D3N"].Visible = (filtro != "AULAS" && filtro != "LABORATORIO");

            lblStatusCount.Text = string.Format("Total Consolidados: {0}  |  Mostrando en vista ({1}): {2}", tableTodos.Rows.Count, filtro, dv.Count);
        }

        private void Grid_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= grid.Rows.Count) return;
            DataGridViewRow row = grid.Rows[e.RowIndex];
            bool needsValidation = false;
            foreach (DataGridViewCell c in row.Cells)
            {
                if (c.Value != null && c.Value.ToString().IndexOf("validar", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    needsValidation = true;
                    break;
                }
            }
            if (needsValidation)
                row.DefaultCellStyle.BackColor = Color.FromArgb(254, 249, 195);
            else
                row.DefaultCellStyle.BackColor = Color.White;
        }

        private void BtnAsistTec_Click(object sender, EventArgs e)
        {
            string numStr = PromptInput("T\u00E9cnicos en Sede", "\u00BFCu\u00E1ntos t\u00E9cnicos est\u00E1n realizando el inventario en esta sede? (1 a 10):", "2");
            int num = 0;
            if (!int.TryParse(numStr, out num) || num < 1 || num > 10) return;

            List<string> lista = new List<string>();
            for (int i = 1; i <= num; i++)
            {
                string raw = PromptInput("T\u00E9cnico #" + i, "Ingresa PRIMER NOMBRE y PRIMER APELLIDO del T\u00E9cnico #" + i + ":", "");
                if (string.IsNullOrWhiteSpace(raw)) return;
                string[] parts = raw.Trim().ToUpper().Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                string fmt;
                if (parts.Length >= 4) fmt = parts[0] + " " + parts[2];
                else if (parts.Length >= 2) fmt = parts[0] + " " + parts[1];
                else fmt = parts[0];
                lista.Add(fmt);
            }
            tecnicosResponsables = string.Join("/", lista.ToArray());
            txtTec.Text = tecnicosResponsables;
            SaveConfig();
            if (tableTodos != null)
            {
                foreach (DataRow r in tableTodos.Rows)
                    r["TECNICO RESPONSABLE"] = tecnicosResponsables;
                // No es una correccion manual: actualizar las referencias para que no se guarde como Ajuste Manual
                int it = ColIdx("TECNICO RESPONSABLE");
                foreach (string[] snap in calcByFile.Values) snap[it] = tecnicosResponsables;
                foreach (string[] snap in loadedByFile.Values) snap[it] = tecnicosResponsables;
            }
        }

        private void BtnAddRow_Click(object sender, EventArgs e)
        {
            if (tableTodos == null) LoadTxtFilesIntoTable();
            string cat = cmbFiltro.Text == "TODOS" ? "ADMINISTRATIVOS" : cmbFiltro.Text;
            DataRow r = tableTodos.NewRow();
            r["TIPO"] = "PC";
            r["PISO"] = "1";
            r["ESTADO"] = "OPERATIVO";
            r["MARCA"] = "HP";
            r["AULA / LAB / ADMINISTRATIVO"] = cat == "ADMINISTRATIVOS" ? "ADMINISTRATIVO" : cat;
            r["FECHA DE INVENTARIO"] = DateTime.Now.ToString("yyyy-MM-dd");
            r["ORGANIZACI\u00D3N"] = cmbInst.SelectedIndex == 2 ? txtOrgW.Text.Trim().ToUpper() : "IDAC";
            // Fila sin escaneo: el tecnico completa estos valores a mano si los conoce
            r["ANTIVIRUS"] = NO_VERIFICADO;
            r["ABSOLUTE"] = NO_VERIFICADO;
            r["HP INSIGHTS"] = CalcHpInsights(Convert.ToString(r["MARCA"]), "");
            r["TECNICO RESPONSABLE"] = txtTec.Text.Trim().ToUpper();
            r["OBSERVACI\u00D3N"] = "NINGUNA";
            r["_CATEGORIA_INTERNA"] = cat;
            tableTodos.Rows.Add(r);
            ApplyGridFilter();
        }

        private void BtnDelRow_Click(object sender, EventArgs e)
        {
            if (grid.SelectedRows.Count == 0) return;
            foreach (DataGridViewRow gr in grid.SelectedRows)
            {
                if (!gr.IsNewRow) grid.Rows.Remove(gr);
            }
        }

        private List<string[]> GetRowsByCategory(string cat, int colCount)
        {
            grid.EndEdit();
            List<string[]> list = new List<string[]>();
            if (tableTodos == null) return list;

            foreach (DataRow r in tableTodos.Rows)
            {
                if (r.RowState == DataRowState.Deleted) continue;
                string rowCat = r["_CATEGORIA_INTERNA"] != null ? r["_CATEGORIA_INTERNA"].ToString() : "ADMINISTRATIVOS";
                if (cat != "TODOS" && !string.Equals(rowCat, cat, StringComparison.OrdinalIgnoreCase))
                    continue;

                string[] arr = new string[colCount];
                for (int i = 0; i < colCount; i++)
                    arr[i] = r[i] != null ? r[i].ToString() : "";
                list.Add(arr);
            }
            return list;
        }

        private void CopyFilteredRowsToClipboard(string targetCat)
        {
            if (tableTodos == null || tableTodos.Rows.Count == 0) LoadTxtFilesIntoTable();
            string cat = targetCat == "VISTA_ACTUAL" ? cmbFiltro.Text : targetCat;
            int cols = (cat == "AULAS" || cat == "LABORATORIO") ? 26 : 27;

            List<string[]> rows = GetRowsByCategory(cat, cols);
            if (rows.Count == 0)
            {
                MessageBox.Show("No hay filas en la categor\u00EDa " + cat + " para copiar.", "Sin Filas", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < rows.Count; i++)
            {
                if (i > 0) sb.Append("\r\n");
                sb.Append(string.Join("\t", rows[i]));
            }
            Clipboard.SetText(sb.ToString());
            MessageBox.Show(
                string.Format("Se copiaron {0} filas de {1} al portapapeles (incluyendo tus ediciones en la tabla).\n\nVe a tu Excel en la nube y presiona Ctrl + V.", rows.Count, cat),
                "Copiado al Portapapeles", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // ===================== Pestana 2: correcciones manuales persistentes en el .txt =====================

        private int ColIdx(string name)
        {
            for (int i = 0; i < headersAdm.Length; i++)
            {
                if (string.Equals(headersAdm[i], name, StringComparison.OrdinalIgnoreCase)) return i;
            }
            return -1;
        }

        private string[] GetRowValues(DataRow row)
        {
            string[] v = new string[headersAdm.Length];
            for (int i = 0; i < headersAdm.Length; i++) v[i] = Convert.ToString(row[i]);
            return v;
        }

        private void CommitGridEdit()
        {
            if (grid == null) return;
            try
            {
                grid.EndEdit();
                if (grid.DataSource != null && grid.BindingContext != null)
                    grid.BindingContext[grid.DataSource].EndCurrentEdit();
            }
            catch { }
        }

        // Filas cargadas desde .txt cuyo contenido cambio respecto a lo que se cargo
        private List<DataRow> GetPendingGridRows()
        {
            List<DataRow> list = new List<DataRow>();
            if (tableTodos == null) return list;
            CommitGridEdit();
            foreach (DataRow row in tableTodos.Rows)
            {
                if (row.RowState == DataRowState.Deleted || row.RowState == DataRowState.Detached) continue;
                string path = Convert.ToString(row["_ARCHIVO"]);
                string[] loaded;
                if (path.Length == 0 || !loadedByFile.TryGetValue(path, out loaded)) continue;
                string[] cur = GetRowValues(row);
                for (int i = 0; i < cur.Length; i++)
                {
                    if (!string.Equals(cur[i], loaded[i], StringComparison.Ordinal))
                    {
                        list.Add(row);
                        break;
                    }
                }
            }
            return list;
        }

        // Guarda en el .txt como "Ajuste Manual" cada columna que difiere del valor calculado desde el escaneo
        private void SaveRowAjustesToTxt(DataRow row)
        {
            string path = Convert.ToString(row["_ARCHIVO"]);
            string[] calc;
            if (path.Length == 0 || !calcByFile.TryGetValue(path, out calc) || !File.Exists(path)) return;

            string[] cur = GetRowValues(row);
            InventoryReport rep = ParseReport(File.ReadAllLines(path, Encoding.UTF8));
            rep.Ajustes.Clear();
            for (int i = 0; i < cur.Length; i++)
            {
                if (!string.Equals(cur[i].Trim(), calc[i].Trim(), StringComparison.Ordinal))
                    rep.Ajustes.Add(new KeyValuePair<string, string>(headersAdm[i], OneLine(cur[i])));
            }
            File.WriteAllLines(path, ReportToLines(rep).ToArray(), Encoding.UTF8);
            loadedByFile[path] = cur;
        }

        private int SaveGridRows(List<DataRow> rows)
        {
            int ok = 0;
            List<string> errores = new List<string>();
            foreach (DataRow row in rows)
            {
                try
                {
                    SaveRowAjustesToTxt(row);
                    ok++;
                }
                catch (Exception ex)
                {
                    errores.Add(Convert.ToString(row["HOST NAME"]) + ": " + ex.Message);
                }
            }
            if (errores.Count > 0)
            {
                MessageBox.Show("No se pudieron guardar algunos equipos:\n\n" + string.Join("\n", errores.ToArray()),
                    "Error al Guardar", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            return ok;
        }

        private void BtnSaveGrid_Click(object sender, EventArgs e)
        {
            List<DataRow> rows = GetPendingGridRows();
            if (rows.Count == 0)
            {
                MessageBox.Show("No hay cambios en la tabla pendientes de guardar en los .txt.\n\n(Las filas manuales y las filas eliminadas solo afectan a la exportaci\u00F3n.)",
                    "Sin Cambios", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            int n = SaveGridRows(rows);
            lblStatusText.Text = string.Format("Se guardaron los cambios de {0} equipo(s) en sus .txt.", n);
            MessageBox.Show(string.Format("Se guardaron los cambios de {0} equipo(s) en sus archivos .txt como correcciones manuales (Ajuste Manual).\n\nSe conservar\u00E1n al recargar la tabla y en las pr\u00F3ximas exportaciones.", n),
                "Cambios Guardados", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // true = se puede continuar (guardado o descartado); false = el usuario cancelo
        private bool ConfirmSaveOrDiscardGridChanges()
        {
            List<DataRow> rows = GetPendingGridRows();
            if (rows.Count == 0) return true;
            DialogResult dr = MessageBox.Show(
                string.Format("Hay cambios en la tabla de {0} equipo(s) que no se han guardado en sus .txt.\n\n\u00BFDeseas guardarlos antes de continuar?\n\nS\u00ED = guardar     No = descartar     Cancelar = volver a la tabla", rows.Count),
                "Cambios sin Guardar", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Warning);
            if (dr == DialogResult.Cancel) return false;
            if (dr == DialogResult.Yes) SaveGridRows(rows);
            return true;
        }

        // ===================== Comparacion con el Excel exportado anterior =====================

        private class ExcelCellDiff
        {
            public string Host;
            public string Column;
            public string OldVal;
            public string NewVal;
            public DataRow Row;
            public bool UseOld;
        }

        private class ExcelMissingRow
        {
            public string Host;
            public Dictionary<string, string> Values;
            public bool Keep = true;
        }

        private static XmlDocument LoadZipXml(ZipArchive zip, string entryName)
        {
            ZipArchiveEntry entry = zip.GetEntry(entryName);
            if (entry == null) return null;
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null;
            using (Stream s = entry.Open()) doc.Load(s);
            return doc;
        }

        private static int ColumnIndexFromRef(string cellRef)
        {
            int idx = 0;
            foreach (char ch in cellRef.ToUpperInvariant())
            {
                if (ch < 'A' || ch > 'Z') break;
                idx = idx * 26 + (ch - 'A' + 1);
            }
            return idx;
        }

        // Lee la hoja TODOS (o la primera) de un .xlsx: generado por este programa o guardado despues con Excel
        private bool TryReadPreviousExport(string path, out Dictionary<string, Dictionary<string, string>> rowsByHost, out string error)
        {
            rowsByHost = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
            error = "";
            const string nsMain = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
            const string nsRel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
            const string nsPkg = "http://schemas.openxmlformats.org/package/2006/relationships";
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Read))
                {
                    XmlDocument wb = LoadZipXml(zip, "xl/workbook.xml");
                    XmlDocument rels = LoadZipXml(zip, "xl/_rels/workbook.xml.rels");
                    if (wb == null || rels == null) { error = "El archivo no tiene la estructura de un .xlsx."; return false; }

                    string relId = null;
                    string firstRelId = null;
                    foreach (XmlElement sh in wb.GetElementsByTagName("sheet", nsMain))
                    {
                        string rid = sh.GetAttribute("id", nsRel);
                        if (firstRelId == null) firstRelId = rid;
                        if (string.Equals(sh.GetAttribute("name"), "TODOS", StringComparison.OrdinalIgnoreCase)) relId = rid;
                    }
                    if (relId == null) relId = firstRelId;
                    if (relId == null) { error = "El Excel no contiene hojas."; return false; }

                    string target = null;
                    foreach (XmlElement rel in rels.GetElementsByTagName("Relationship", nsPkg))
                    {
                        if (rel.GetAttribute("Id") == relId) target = rel.GetAttribute("Target");
                    }
                    if (string.IsNullOrEmpty(target)) { error = "No se encontr\u00F3 la hoja TODOS."; return false; }
                    string sheetEntry = target.StartsWith("/") ? target.TrimStart('/') : "xl/" + target;

                    List<string> shared = new List<string>();
                    XmlDocument sst = LoadZipXml(zip, "xl/sharedStrings.xml");
                    if (sst != null)
                    {
                        foreach (XmlElement item in sst.GetElementsByTagName("si", nsMain))
                        {
                            StringBuilder sbs = new StringBuilder();
                            foreach (XmlElement t in item.GetElementsByTagName("t", nsMain))
                            {
                                if (t.ParentNode != null && t.ParentNode.LocalName == "rPh") continue;
                                sbs.Append(t.InnerText);
                            }
                            shared.Add(sbs.ToString());
                        }
                    }

                    XmlDocument sheet = LoadZipXml(zip, sheetEntry);
                    if (sheet == null) { error = "No se pudo leer la hoja " + sheetEntry; return false; }

                    Dictionary<int, string> headers = null;
                    foreach (XmlElement rowEl in sheet.GetElementsByTagName("row", nsMain))
                    {
                        Dictionary<int, string> cells = new Dictionary<int, string>();
                        int pos = 0;
                        foreach (XmlNode node in rowEl.ChildNodes)
                        {
                            XmlElement c = node as XmlElement;
                            if (c == null || c.LocalName != "c") continue;
                            pos++;
                            string cref = c.GetAttribute("r");
                            int col = string.IsNullOrEmpty(cref) ? pos : ColumnIndexFromRef(cref);
                            pos = col;
                            string type = c.GetAttribute("t");
                            string val;
                            if (type == "inlineStr")
                            {
                                StringBuilder sbi = new StringBuilder();
                                foreach (XmlElement t in c.GetElementsByTagName("t", nsMain)) sbi.Append(t.InnerText);
                                val = sbi.ToString();
                            }
                            else
                            {
                                XmlNodeList vs = c.GetElementsByTagName("v", nsMain);
                                string raw = vs.Count > 0 ? vs[0].InnerText : "";
                                int sIdx;
                                if (type == "s" && int.TryParse(raw, out sIdx) && sIdx >= 0 && sIdx < shared.Count) val = shared[sIdx];
                                else val = raw;
                            }
                            cells[col] = val;
                        }

                        if (headers == null)
                        {
                            headers = cells;
                            continue;
                        }

                        Dictionary<string, string> data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        foreach (KeyValuePair<int, string> h in headers)
                        {
                            string name = (h.Value ?? "").Trim();
                            if (name.Length == 0 || data.ContainsKey(name)) continue;
                            string cv;
                            data[name] = cells.TryGetValue(h.Key, out cv) ? cv : "";
                        }
                        string host;
                        if (!data.TryGetValue("HOST NAME", out host) || string.IsNullOrWhiteSpace(host)) continue;
                        rowsByHost[host.Trim()] = data;
                    }

                    bool tieneHost = false;
                    if (headers != null)
                    {
                        foreach (string hv in headers.Values)
                            if (string.Equals((hv ?? "").Trim(), "HOST NAME", StringComparison.OrdinalIgnoreCase)) tieneHost = true;
                    }
                    if (!tieneHost) { error = "La hoja no tiene la columna HOST NAME."; return false; }
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private void ComputeExcelComparison(Dictionary<string, Dictionary<string, string>> anteriores,
            List<ExcelCellDiff> diffs, List<ExcelMissingRow> missing, List<string> nuevos)
        {
            CommitGridEdit();
            HashSet<string> actuales = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (DataRow row in tableTodos.Rows)
            {
                if (row.RowState == DataRowState.Deleted || row.RowState == DataRowState.Detached) continue;
                string host = Convert.ToString(row["HOST NAME"]).Trim();
                if (host.Length == 0) continue;
                actuales.Add(host);

                Dictionary<string, string> previo;
                if (!anteriores.TryGetValue(host, out previo))
                {
                    nuevos.Add(host);
                    continue;
                }
                foreach (string col in headersAdm)
                {
                    if (col == "FECHA DE INVENTARIO") continue;
                    string ov;
                    if (!previo.TryGetValue(col, out ov)) continue;
                    ov = (ov ?? "").Trim();
                    string nv = Convert.ToString(row[col]).Trim();
                    if (string.Equals(ov, nv, StringComparison.Ordinal)) continue;
                    ExcelCellDiff d = new ExcelCellDiff();
                    d.Host = host; d.Column = col; d.OldVal = ov; d.NewVal = nv; d.Row = row;
                    diffs.Add(d);
                }
            }
            foreach (KeyValuePair<string, Dictionary<string, string>> kv in anteriores)
            {
                if (actuales.Contains(kv.Key)) continue;
                ExcelMissingRow m = new ExcelMissingRow();
                m.Host = kv.Key;
                m.Values = kv.Value;
                missing.Add(m);
            }
        }

        private void ApplyExcelChoices(List<ExcelCellDiff> diffs, List<ExcelMissingRow> missing)
        {
            // MARCA primero: asi la regla de HP INSIGHTS se recalcula antes que el resto de columnas
            List<ExcelCellDiff> elegidos = diffs.Where(x => x.UseOld).OrderBy(x => x.Column == "MARCA" ? 0 : 1).ToList();
            List<DataRow> tocadas = new List<DataRow>();
            foreach (ExcelCellDiff d in elegidos)
            {
                d.Row[d.Column] = d.OldVal;
                if (!tocadas.Contains(d.Row)) tocadas.Add(d.Row);
            }
            // La decision "mantener dato del Excel" se guarda en el .txt para no volver a preguntar
            if (tocadas.Count > 0) SaveGridRows(tocadas);

            foreach (ExcelMissingRow m in missing)
            {
                if (!m.Keep) continue;
                DataRow r = tableTodos.NewRow();
                foreach (string col in headersAdm)
                {
                    string v;
                    r[col] = m.Values.TryGetValue(col, out v) ? v : "";
                }
                string amb = Convert.ToString(r["AULA / LAB / ADMINISTRATIVO"]).Trim().ToUpper();
                string cat = "ADMINISTRATIVOS";
                if (amb.StartsWith("AULA")) cat = "AULAS";
                else if (amb.StartsWith("LAB")) cat = "LABORATORIO";
                r["_CATEGORIA_INTERNA"] = cat;
                r["_ARCHIVO"] = "";
                tableTodos.Rows.Add(r);
            }
            ApplyGridFilter();
        }

        // false = el usuario cancelo la exportacion
        private bool RunExcelComparison(Dictionary<string, Dictionary<string, string>> anteriores, out int nuevosCount)
        {
            List<ExcelCellDiff> diffs = new List<ExcelCellDiff>();
            List<ExcelMissingRow> missing = new List<ExcelMissingRow>();
            List<string> nuevos = new List<string>();
            ComputeExcelComparison(anteriores, diffs, missing, nuevos);
            nuevosCount = nuevos.Count;
            if (diffs.Count == 0 && missing.Count == 0) return true;
            if (!ShowExcelCompareDialog(diffs, missing, nuevos)) return false;
            ApplyExcelChoices(diffs, missing);
            return true;
        }

        private bool ShowExcelCompareDialog(List<ExcelCellDiff> diffs, List<ExcelMissingRow> missing, List<string> nuevos)
        {
            Form f = new Form();
            f.Text = "Comparaci\u00F3n con el Excel exportado anterior";
            f.Size = new Size(1040, 660);
            f.MinimumSize = new Size(800, 460);
            f.StartPosition = FormStartPosition.CenterParent;
            f.MinimizeBox = false;
            f.ShowInTaskbar = false;
            f.Font = new Font("Segoe UI", 9F);

            HashSet<string> hostsCambiados = new HashSet<string>(diffs.Select(x => x.Host), StringComparer.OrdinalIgnoreCase);
            Label lbl = new Label();
            lbl.Dock = DockStyle.Top;
            lbl.Padding = new Padding(10, 8, 10, 0);
            lbl.Text = string.Format(
                "Se compararon los datos actuales con el Excel exportado anteriormente (por HOST NAME; la FECHA DE INVENTARIO no se compara).\nCampos distintos: {0} en {1} equipo(s)   |   Equipos nuevos: {2}   |   Equipos que ya no est\u00E1n: {3}",
                diffs.Count, hostsCambiados.Count, nuevos.Count, missing.Count);
            lbl.Height = 52;
            if (nuevos.Count > 0)
            {
                lbl.Text += "\nEquipos nuevos (se agregan al Excel): " + string.Join(", ", nuevos.Take(15).ToArray()) + (nuevos.Count > 15 ? " ..." : "");
                lbl.Height = 70;
            }

            DataGridView g1 = null;
            Panel pnlDiff = null;
            if (diffs.Count > 0)
            {
                pnlDiff = new Panel();
                pnlDiff.Dock = DockStyle.Fill;
                pnlDiff.Padding = new Padding(10, 0, 10, 0);

                FlowLayoutPanel bar = new FlowLayoutPanel();
                bar.Dock = DockStyle.Top;
                bar.Height = 44;
                Button bNew = DialogButton("Aceptar todos los datos nuevos", 220, Color.FromArgb(224, 242, 254), Color.Black);
                Button bOld = DialogButton("Mantener todos los del Excel", 210, Color.FromArgb(226, 232, 240), Color.Black);
                Label hint = new Label();
                hint.Text = "O elige campo por campo en la columna \"Usar\".";
                hint.AutoSize = true;
                hint.Margin = new Padding(12, 15, 0, 0);
                bar.Controls.Add(bNew);
                bar.Controls.Add(bOld);
                bar.Controls.Add(hint);

                g1 = NewCompareGrid();
                g1.Columns.Add(TextCol("Equipo", 16));
                g1.Columns.Add(TextCol("Campo", 18));
                g1.Columns.Add(TextCol("Excel anterior", 27));
                g1.Columns.Add(TextCol("Actual (.txt / tabla)", 27));
                g1.Columns.Add(ChoiceCol("Usar", 14, new string[] { "Actual", "Excel anterior" }));
                foreach (ExcelCellDiff d in diffs) g1.Rows.Add(d.Host, d.Column, d.OldVal, d.NewVal, "Actual");

                DataGridView gRef = g1;
                bNew.Click += delegate { foreach (DataGridViewRow gr in gRef.Rows) gr.Cells[4].Value = "Actual"; };
                bOld.Click += delegate { foreach (DataGridViewRow gr in gRef.Rows) gr.Cells[4].Value = "Excel anterior"; };

                pnlDiff.Controls.Add(g1);
                pnlDiff.Controls.Add(bar);
            }

            DataGridView g2 = null;
            Panel pnlMiss = null;
            if (missing.Count > 0)
            {
                pnlMiss = new Panel();
                pnlMiss.Padding = new Padding(10, 4, 10, 4);
                Label lm = new Label();
                lm.Text = "Equipos que estaban en el Excel anterior y ya no tienen .txt. Marca \"Conservar\" para mantenerlos en el nuevo Excel:";
                lm.Dock = DockStyle.Top;
                lm.Height = 24;
                g2 = NewCompareGrid();
                g2.Columns.Add(TextCol("Equipo", 22));
                g2.Columns.Add(TextCol("\u00C1rea", 30));
                g2.Columns.Add(TextCol("Aula / Lab / Administrativo", 30));
                DataGridViewCheckBoxColumn keepCol = new DataGridViewCheckBoxColumn();
                keepCol.HeaderText = "Conservar";
                keepCol.FillWeight = 12;
                keepCol.SortMode = DataGridViewColumnSortMode.NotSortable;
                g2.Columns.Add(keepCol);
                foreach (ExcelMissingRow m in missing)
                {
                    string area, amb;
                    if (!m.Values.TryGetValue("AREA", out area)) area = "";
                    if (!m.Values.TryGetValue("AULA / LAB / ADMINISTRATIVO", out amb)) amb = "";
                    g2.Rows.Add(m.Host, area, amb, m.Keep);
                }
                pnlMiss.Controls.Add(g2);
                pnlMiss.Controls.Add(lm);
            }

            FlowLayoutPanel bottom = new FlowLayoutPanel();
            bottom.Dock = DockStyle.Bottom;
            bottom.Height = 54;
            bottom.FlowDirection = FlowDirection.RightToLeft;
            bottom.Padding = new Padding(0, 4, 10, 0);
            Button bCancel = DialogButton("Cancelar Exportaci\u00F3n", 170, Color.FromArgb(241, 245, 249), Color.Black);
            Button bOk = DialogButton("Aplicar y Exportar", 190, Color.FromArgb(21, 128, 61), Color.White);
            bottom.Controls.Add(bCancel);
            bottom.Controls.Add(bOk);

            if (pnlDiff != null)
            {
                f.Controls.Add(pnlDiff);
                if (pnlMiss != null)
                {
                    pnlMiss.Dock = DockStyle.Bottom;
                    pnlMiss.Height = 200;
                    f.Controls.Add(pnlMiss);
                }
            }
            else if (pnlMiss != null)
            {
                pnlMiss.Dock = DockStyle.Fill;
                f.Controls.Add(pnlMiss);
            }
            f.Controls.Add(bottom);
            f.Controls.Add(lbl);

            bool aplicar = false;
            DataGridView g1Ref = g1;
            DataGridView g2Ref = g2;
            bOk.Click += delegate
            {
                if (g1Ref != null) g1Ref.EndEdit();
                if (g2Ref != null) g2Ref.EndEdit();
                aplicar = true;
                f.Close();
            };
            bCancel.Click += delegate { f.Close(); };
            f.ShowDialog(this);
            if (!aplicar) return false;

            if (g1 != null)
            {
                for (int i = 0; i < diffs.Count; i++)
                    diffs[i].UseOld = string.Equals(Convert.ToString(g1.Rows[i].Cells[4].Value), "Excel anterior", StringComparison.Ordinal);
            }
            if (g2 != null)
            {
                for (int i = 0; i < missing.Count; i++)
                {
                    object cv = g2.Rows[i].Cells[3].Value;
                    missing[i].Keep = cv is bool && (bool)cv;
                }
            }
            return true;
        }

        private void BtnExportXlsx_Click(object sender, EventArgs e)
        {
            if (tableTodos == null || tableTodos.Rows.Count == 0) LoadTxtFilesIntoTable();
            if (tableTodos.Rows.Count == 0)
            {
                MessageBox.Show("No hay equipos registrados para exportar a Excel.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string sufijo = cmbInst.SelectedIndex == 1 ? "Carrion" : (cmbInst.SelectedIndex == 2 ? "Wiener" : "General");
            string xlsxPath = Path.Combine(baseDir, "Inventario_Consolidado_" + sufijo + ".xlsx");

            // Comparar con el Excel exportado anterior antes de reemplazarlo
            int nuevosVsAnterior = -1;
            if (File.Exists(xlsxPath))
            {
                Dictionary<string, Dictionary<string, string>> anteriores;
                string errLectura;
                if (TryReadPreviousExport(xlsxPath, out anteriores, out errLectura))
                {
                    if (!RunExcelComparison(anteriores, out nuevosVsAnterior)) return;
                }
                else
                {
                    DialogResult drSin = MessageBox.Show(
                        "No se pudo leer el Excel anterior para comparar los cambios:\n" + errLectura + "\n\n(Si est\u00E1 abierto en Excel, ci\u00E9rralo y vuelve a exportar.)\n\n\u00BFDeseas exportar de todas formas sin comparar?",
                        "Comparaci\u00F3n no disponible", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                    if (drSin != DialogResult.Yes) return;
                }
            }

            if (File.Exists(xlsxPath))
            {
                try { File.Delete(xlsxPath); }
                catch { xlsxPath = Path.Combine(baseDir, string.Format("Inventario_Consolidado_{0}_{1}.xlsx", sufijo, DateTime.Now.ToString("HHmmss"))); }
            }

            string[] headers26 = headersAdm.Take(26).ToArray();
            List<string[]> rowsAdm = GetRowsByCategory("ADMINISTRATIVOS", 27);
            List<string[]> rowsAu  = GetRowsByCategory("AULAS", 26);
            List<string[]> rowsLab = GetRowsByCategory("LABORATORIO", 26);
            List<string[]> rowsAll = GetRowsByCategory("TODOS", 27);

            WriteConsolidatedXlsx(xlsxPath, headers26, rowsAdm, rowsAu, rowsLab, rowsAll);

            DialogResult open = MessageBox.Show(
                string.Format("Archivo Excel generado exitosamente en:\n{0}\n\n- ADMINISTRATIVOS: {1}\n- AULAS: {2}\n- LABORATORIO: {3}{4}\n\n\u00BFDeseas abrir el archivo Excel ahora?", xlsxPath, rowsAdm.Count, rowsAu.Count, rowsLab.Count, nuevosVsAnterior >= 0 ? "\n- Equipos nuevos respecto al Excel anterior: " + nuevosVsAnterior : ""),
                "Excel Generado", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
            if (open == DialogResult.Yes)
                Process.Start(xlsxPath);
        }

        private void WriteConsolidatedXlsx(string xlsxPath, string[] headers26, List<string[]> rowsAdm, List<string[]> rowsAu, List<string[]> rowsLab, List<string[]> rowsAll)
        {
            using (FileStream fs = new FileStream(xlsxPath, FileMode.Create))
            using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Create))
            {
                WriteZipEntry(zip, "[Content_Types].xml",
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/worksheets/sheet2.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/worksheets/sheet3.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/worksheets/sheet4.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/></Types>");

                WriteZipEntry(zip, "_rels/.rels",
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>");

                WriteZipEntry(zip, "xl/workbook.xml",
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"ADMINISTRATIVOS\" sheetId=\"1\" r:id=\"rId1\"/><sheet name=\"AULAS\" sheetId=\"2\" r:id=\"rId2\"/><sheet name=\"LABORATORIO\" sheetId=\"3\" r:id=\"rId3\"/><sheet name=\"TODOS\" sheetId=\"4\" r:id=\"rId4\"/></sheets></workbook>");

                WriteZipEntry(zip, "xl/_rels/workbook.xml.rels",
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet2.xml\"/><Relationship Id=\"rId3\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet3.xml\"/><Relationship Id=\"rId4\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet4.xml\"/><Relationship Id=\"rId5\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/></Relationships>");

                WriteZipEntry(zip, "xl/styles.xml",
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><fonts count=\"2\"><font><sz val=\"10\"/><name val=\"Calibri\"/></font><font><b/><sz val=\"10\"/><color rgb=\"FFFFFFFF\"/><name val=\"Calibri\"/></font></fonts><fills count=\"3\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill><fill><patternFill patternType=\"solid\"><fgColor rgb=\"FF1E293B\"/></patternFill></fill></fills><borders count=\"2\"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style=\"thin\"><color rgb=\"FFD9D9D9\"/></left><right style=\"thin\"><color rgb=\"FFD9D9D9\"/></right><top style=\"thin\"><color rgb=\"FFD9D9D9\"/></top><bottom style=\"thin\"><color rgb=\"FFD9D9D9\"/></bottom><diagonal/></border></borders><cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs><cellXfs count=\"3\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/><xf numFmtId=\"0\" fontId=\"1\" fillId=\"2\" borderId=\"1\" xfId=\"0\" applyFont=\"1\" applyFill=\"1\" applyBorder=\"1\"/><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"1\" xfId=\"0\" applyBorder=\"1\"/></cellXfs></styleSheet>");

                WriteZipEntry(zip, "xl/worksheets/sheet1.xml", BuildSheetXml(headersAdm, rowsAdm));
                WriteZipEntry(zip, "xl/worksheets/sheet2.xml", BuildSheetXml(headers26, rowsAu));
                WriteZipEntry(zip, "xl/worksheets/sheet3.xml", BuildSheetXml(headers26, rowsLab));
                WriteZipEntry(zip, "xl/worksheets/sheet4.xml", BuildSheetXml(headersAdm, rowsAll));
            }
        }

        private string GetColLetter(int colIndex)
        {
            int div = colIndex;
            string colLetter = "";
            while (div > 0)
            {
                int mod = (div - 1) % 26;
                colLetter = (char)(65 + mod) + colLetter;
                div = (div - mod) / 26;
            }
            return colLetter;
        }

        private string BuildSheetXml(string[] headers, List<string[]> rows)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
            sb.Append("<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>");
            sb.Append("<row r=\"1\">");
            for (int c = 0; c < headers.Length; c++)
            {
                string cellRef = GetColLetter(c + 1) + "1";
                string val = SecurityElement.Escape(headers[c] ?? "");
                sb.AppendFormat("<c r=\"{0}\" s=\"1\" t=\"inlineStr\"><is><t>{1}</t></is></c>", cellRef, val);
            }
            sb.Append("</row>");

            for (int r = 0; r < rows.Count; r++)
            {
                int rowNum = r + 2;
                string[] rowArr = rows[r];
                sb.AppendFormat("<row r=\"{0}\">", rowNum);
                for (int c = 0; c < rowArr.Length; c++)
                {
                    string cellRef = GetColLetter(c + 1) + rowNum.ToString();
                    string val = SecurityElement.Escape(rowArr[c] ?? "");
                    sb.AppendFormat("<c r=\"{0}\" s=\"2\" t=\"inlineStr\"><is><t>{1}</t></is></c>", cellRef, val);
                }
                sb.Append("</row>");
            }
            sb.Append("</sheetData></worksheet>");
            return sb.ToString();
        }

        private void WriteZipEntry(ZipArchive zip, string path, string content)
        {
            ZipArchiveEntry entry = zip.CreateEntry(path);
            using (Stream s = entry.Open())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(content);
                s.Write(bytes, 0, bytes.Length);
            }
        }

        private void UpdateTxtCounterBadge()
        {
            try
            {
                int count = GetInventoryTxtFiles().Count;
                lblHeaderStats.Text = string.Format("Reportes .TXT en carpeta: {0}   |   Ruta: {1}", count, baseDir);
            }
            catch { }
        }

        private string PromptInput(string title, string message, string defaultVal)
        {
            Form f = new Form();
            f.Text = title;
            f.Size = new Size(450, 185);
            f.StartPosition = FormStartPosition.CenterParent;
            f.FormBorderStyle = FormBorderStyle.FixedDialog;
            f.MaximizeBox = false;
            f.MinimizeBox = false;

            Label l = new Label() { Text = message, Location = new Point(15, 14), Size = new Size(405, 42) };
            TextBox t = new TextBox() { Text = defaultVal, Location = new Point(15, 62), Size = new Size(405, 25) };
            Button bOk = new Button() { Text = "Aceptar", DialogResult = DialogResult.OK, Location = new Point(250, 100), Size = new Size(80, 28) };
            Button bCa = new Button() { Text = "Cancelar", DialogResult = DialogResult.Cancel, Location = new Point(340, 100), Size = new Size(80, 28) };

            f.Controls.AddRange(new Control[] { l, t, bOk, bCa });
            f.AcceptButton = bOk;
            f.CancelButton = bCa;

            return f.ShowDialog(this) == DialogResult.OK ? t.Text.Trim() : null;
        }
    }

    public static class Program
    {
        // true = se ejecuta como InventarioTI.exe; false = desde Iniciar_Inventario.bat (Add-Type)
        public static bool IsExe = false;

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        // Punto de entrada cuando se compila como InventarioTI.exe (Compilar_Exe.bat).
        // Iniciar_Inventario.bat no usa Main: llama a StartApp() directamente via Add-Type.
        [STAThread]
        public static void Main()
        {
            IsExe = true;
            StartApp();
        }

        [STAThread]
        public static void StartApp()
        {
            IntPtr hConsole = GetConsoleWindow();
            if (hConsole != IntPtr.Zero)
            {
                ShowWindow(hConsole, 0);
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}