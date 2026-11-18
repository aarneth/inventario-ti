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
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

// Metadatos visibles en Propiedades > Detalles del .exe (ayuda a Seguridad TI a identificarlo en Kaspersky)
[assembly: AssemblyTitle("Sistema de Inventario y Auditoria TI")]
[assembly: AssemblyProduct("Inventario TI - Wiener / Carrion")]
[assembly: AssemblyDescription("Levantamiento y consolidacion de inventario de equipos de computo")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

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

    public class ConfigModel
    {
        public string Tecnicos { get; set; }
        public string OrgWiener { get; set; }
        public Dictionary<string, string> Areas { get; set; }
        public Dictionary<string, string> Pisos { get; set; }
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
            this.Size = new Size(1180, 790);
            this.MinimumSize = new Size(1050, 700);
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

            tabs.TabPages.Add(tabScan);
            tabs.TabPages.Add(tabExcel);

            this.Controls.Add(tabs);
            this.Controls.Add(pnlHeader);
            this.Controls.Add(statusStrip);

            BuildTabScan(tabScan);
            BuildTabExcel(tabExcel);

            tabs.SelectedIndexChanged += delegate {
                if (tabs.SelectedIndex == 1) LoadTxtFilesIntoTable();
            };

            this.Shown += delegate {
                ScanCurrentHardware();
                UpdateTxtCounterBadge();
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
                "REMACHE / SIN CADENA",
                "SIN REMACHE/SIN CADENA",
                "REMACHE Y CADENA",
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
            btnRescan.Size = new Size(210, 42);
            btnRescan.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnRescan.BackColor = Color.FromArgb(226, 232, 240);
            btnRescan.FlatStyle = FlatStyle.Flat;
            btnRescan.Click += delegate { ScanCurrentHardware(); };
            page.Controls.Add(btnRescan);

            Button btnSave = new Button();
            btnSave.Text = "GUARDAR REPORTE (.TXT) EN SUBCARPETA Y AUDITAR CAMBIOS";
            btnSave.Location = new Point(234, 598);
            btnSave.Size = new Size(910, 42);
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
            btnReload.Text = "Recargar Subcarpetas (.txt)";
            btnReload.Location = new Point(840, 21);
            btnReload.Size = new Size(275, 28);
            btnReload.BackColor = Color.FromArgb(224, 242, 254);
            btnReload.FlatStyle = FlatStyle.Flat;
            btnReload.Click += delegate { LoadTxtFilesIntoTable(); };
            grpTop.Controls.Add(btnReload);

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

                string hostUpper = csName.ToUpper();
                bool esLaptop = Regex.IsMatch(hostUpper, @"^[A-Z]+\d+LP") ||
                                Regex.IsMatch(tipoEquipo, @"Laptop|Portatil|Notebook|Convertible", RegexOptions.IgnoreCase);

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
                    cmbSeg.Text = esLaptop ? "CADENA DE SEGURIDAD" : "REMACHE / SIN CADENA";
                }
                else if (mAd.Success)
                {
                    string codArea = mAd.Groups[1].Value.ToUpper();
                    cmbCat.Text = "ADMINISTRATIVOS";
                    if (!areaMap.ContainsKey(codArea))
                    {
                        string nuevoNom = PromptInput("Nueva Sigla Detectada",
                            string.Format("El equipo {0} contiene la sigla de área [{1}].\nIngresa el nombre completo del ÁREA (ej. ADMISION, CAJA, RRHH):", hostUpper, codArea), "");
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

                txtTipo.Text   = tipoEquipo;
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

        private List<string> BuildReportLines()
        {
            List<string> lines = new List<string>();
            lines.Add("========================================================");
            lines.Add("              INVENTARIO DE HARDWARE Y RED              ");
            lines.Add("========================================================");
            lines.Add("Categoria Ubicacion: " + (cmbCat != null ? cmbCat.Text.Trim() : ""));
            lines.Add("Area / Ambiente    : " + (cmbArea != null ? cmbArea.Text.Trim().ToUpper() : ""));
            lines.Add("Piso Ubicacion     : " + (txtPiso != null ? txtPiso.Text.Trim().ToUpper() : ""));
            lines.Add("Seguridad Fisica   : " + (cmbSeg != null ? cmbSeg.Text.Trim().ToUpper() : ""));
            lines.Add("--------------------------------------------------------");
            lines.Add("Tipo de Equipo     : " + (txtTipo != null ? txtTipo.Text.Trim() : ""));
            lines.Add("Marca              : " + (txtMarca != null ? txtMarca.Text.Trim() : ""));
            lines.Add("Modelo             : " + (txtModelo != null ? txtModelo.Text.Trim() : ""));
            lines.Add("Serie del Equipo   : " + (txtSerie != null ? txtSerie.Text.Trim() : ""));
            lines.Add("Hostname           : " + (txtHost != null ? txtHost.Text.Trim() : ""));
            lines.Add("Dominio / Grupo    : " + (txtDom != null ? txtDom.Text.Trim() : ""));
            lines.Add("Sistema Operativo  : " + (txtSO != null ? txtSO.Text.Trim() : ""));
            lines.Add("Procesador         : " + (txtCPU != null ? txtCPU.Text.Trim() : ""));
            lines.Add("Memoria RAM        : " + (txtRAM != null ? txtRAM.Text.Trim() : ""));
            lines.Add("Almacenamiento     : " + (txtDisk != null ? txtDisk.Text.Trim() : ""));
            lines.Add("--------------------------------------------------------");

            string[] uSplit = (txtUsers != null ? txtUsers.Text : "").Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (uSplit.Length > 0)
            {
                foreach (string u in uSplit) lines.Add("Usuario Equipo     : " + u.Trim());
            }
            else
            {
                lines.Add("Usuario Equipo     : No se detectaron perfiles de usuario (validar presencialmente)");
            }

            if (activeNets.Count > 0)
            {
                foreach (NetAdapterInfo nb in activeNets)
                {
                    lines.Add("--------------------------------------------------------");
                    lines.Add("Adaptador Activo   : " + nb.Description);
                    lines.Add("Direccion IPv4     : " + nb.IPv4);
                    lines.Add("Puerta de Enlace   : " + nb.Gateway);
                    lines.Add("Servidores DNS     : " + nb.DNS);
                    lines.Add("MAC Address        : " + nb.MAC);
                }
            }
            else
            {
                lines.Add("--------------------------------------------------------");
                lines.Add("Red Activa         : Sin conexion activa a red (validar cable/Wi-Fi presencialmente)");
            }

            lines.Add("--------------------------------------------------------");
            string[] mSplit = (txtMons != null ? txtMons.Text : "").Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (mSplit.Length > 0)
            {
                foreach (string m in mSplit) lines.Add("Monitor            : " + m.Trim());
            }
            else
            {
                lines.Add("Monitor            : No se detecto monitor o no reporta datos EDID (validar presencialmente)");
            }

            lines.Add("========================================================");
            lines.Add("Fecha de Auditoria : " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            lines.Add("Usuario Ejecutor   : " + currentUserExec);
            return lines;
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

        private void BtnSaveTxt_Click(object sender, EventArgs e)
        {
            string cat = cmbCat.Text.Trim().ToUpper();
            string are = Regex.Replace(cmbArea.Text.Trim().ToUpper(), @"[\\/:*?""<>|]", "-").Trim();
            if (string.IsNullOrEmpty(are)) are = "GENERAL";

            string dirDestino = Path.Combine(Path.Combine(baseDir, cat), are);
            if (!Directory.Exists(dirDestino)) Directory.CreateDirectory(dirDestino);

            string nombreBase = string.Format("{0}.{1}", txtHost.Text.Trim(), txtDom.Text.Trim());
            string rutaArchivo = Path.Combine(dirDestino, nombreBase + ".txt");
            List<string> newLines = BuildReportLines();

            if (File.Exists(rutaArchivo))
            {
                string[] oldLines = File.ReadAllLines(rutaArchivo, Encoding.UTF8);
                Func<string, bool> filterAudit = l => !Regex.IsMatch(l, @"^(Fecha de Auditoria|Usuario Ejecutor)\s*:");

                List<string> oldClean = oldLines.Where(filterAudit).ToList();
                List<string> newClean = newLines.Where(filterAudit).ToList();

                List<string> removed = oldClean.Except(newClean).ToList();
                List<string> added = newClean.Except(oldClean).ToList();

                if (removed.Count == 0 && added.Count == 0)
                {
                    DialogResult dr = MessageBox.Show(
                        string.Format("El archivo {0}.txt ya existe en {1}\\{2} y NO presenta cambios.\n\n\u00BFDeseas actualizar la fecha de auditor\u00EDa de todas formas?", nombreBase, cat, are),
                        "Sin Cambios Detectados", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                    if (dr == DialogResult.Yes)
                    {
                        File.WriteAllLines(rutaArchivo, newLines.ToArray(), Encoding.UTF8);
                        lblStatusText.Text = "Fecha de auditor\u00EDa actualizada en " + rutaArchivo;
                    }
                    return;
                }

                int op = ShowDiffDialog(nombreBase, removed, added);
                if (op == 1)
                {
                    File.WriteAllLines(rutaArchivo, newLines.ToArray(), Encoding.UTF8);
                    MessageBox.Show("Archivo sobrescrito exitosamente:\n" + rutaArchivo, "Sobrescrito", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else if (op == 2)
                {
                    string histPath = Path.Combine(dirDestino, string.Format("{0}_{1}.txt", nombreBase, DateTime.Now.ToString("yyyyMMdd_HHmmss")));
                    File.WriteAllLines(histPath, newLines.ToArray(), Encoding.UTF8);
                    MessageBox.Show("Copia hist\u00F3rica guardada en:\n" + histPath, "Historial Guardado", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            else
            {
                File.WriteAllLines(rutaArchivo, newLines.ToArray(), Encoding.UTF8);
                MessageBox.Show("Reporte guardado en subcarpeta:\n" + rutaArchivo, "Reporte Guardado", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            UpdateTxtCounterBadge();
        }

        private int ShowDiffDialog(string nombreBase, List<string> removed, List<string> added)
        {
            Form df = new Form();
            df.Text = "Auditor\u00EDa de Diferencias - " + nombreBase + ".txt";
            df.Size = new Size(740, 450);
            df.StartPosition = FormStartPosition.CenterParent;
            df.FormBorderStyle = FormBorderStyle.FixedDialog;
            df.MaximizeBox = false;

            Label lbl = new Label();
            lbl.Text = "Se detectaron cambios respecto al inventario anterior de este equipo. Selecciona qu\u00E9 acci\u00F3n realizar:";
            lbl.Location = new Point(15, 12);
            lbl.Size = new Size(695, 22);
            df.Controls.Add(lbl);

            RichTextBox rtb = new RichTextBox();
            rtb.Location = new Point(15, 38);
            rtb.Size = new Size(695, 305);
            rtb.Font = new Font("Consolas", 9.5F);
            rtb.ReadOnly = true;
            rtb.BackColor = Color.FromArgb(15, 23, 42);

            foreach (string r in removed)
            {
                rtb.SelectionColor = Color.FromArgb(248, 113, 113);
                rtb.AppendText("[ANTERIOR] " + r + Environment.NewLine);
            }
            foreach (string a in added)
            {
                rtb.SelectionColor = Color.FromArgb(74, 222, 128);
                rtb.AppendText("[ACTUAL]   " + a + Environment.NewLine);
            }
            df.Controls.Add(rtb);

            int choice = 3;
            Button b1 = new Button() { Text = "1. Sobrescribir Existente", Location = new Point(15, 355), Size = new Size(220, 38), BackColor = Color.FromArgb(37, 99, 235), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            Button b2 = new Button() { Text = "2. Guardar Historial con Fecha", Location = new Point(248, 355), Size = new Size(230, 38), BackColor = Color.FromArgb(21, 128, 61), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            Button b3 = new Button() { Text = "3. Cancelar", Location = new Point(490, 355), Size = new Size(220, 38), FlatStyle = FlatStyle.Flat };

            b1.Click += delegate { choice = 1; df.Close(); };
            b2.Click += delegate { choice = 2; df.Close(); };
            b3.Click += delegate { choice = 3; df.Close(); };

            df.Controls.Add(b1);
            df.Controls.Add(b2);
            df.Controls.Add(b3);
            df.ShowDialog(this);
            return choice;
        }

        private void LoadTxtFilesIntoTable()
        {
            tecnicosResponsables = txtTec.Text.Trim().ToUpper();
            orgWienerGuardada = txtOrgW.Text.Trim().ToUpper();
            SaveConfig();

            tableTodos = new DataTable("INVENTARIO");
            foreach (string col in headersAdm) tableTodos.Columns.Add(col);
            tableTodos.Columns.Add("_CATEGORIA_INTERNA");

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
                string tipo = (Regex.IsMatch(hostName, @"^[A-Z]+\d+LP") || Regex.IsMatch(tipoRaw, @"Laptop|Portatil|Notebook|Convertible", RegexOptions.IgnoreCase))
                    ? "LAPTOP" : "PC";

                string pestanaDestino = data.ContainsKey("Categoria Ubicacion") ? data["Categoria Ubicacion"].ToUpper() : "ADMINISTRATIVOS";
                string piso = data.ContainsKey("Piso Ubicacion") ? data["Piso Ubicacion"] : "";
                string area = data.ContainsKey("Area / Ambiente") ? data["Area / Ambiente"] : "";
                string remachado = data.ContainsKey("Seguridad Fisica") ? data["Seguridad Fisica"] : "";
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
                    if (string.IsNullOrEmpty(remachado) && tipo == "PC") remachado = "REMACHE / SIN CADENA";
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

                string modelo = data.ContainsKey("Modelo") ? data["Modelo"] : "";
                Match mLen = Regex.Match(modelo, @"\(([^)]+)\)");
                if (mLen.Success && marca == "LENOVO") modelo = mLen.Groups[1].Value.Trim();
                modelo = Regex.Replace(modelo, @"^(HP|Lenovo)\s+", "", RegexOptions.IgnoreCase);
                modelo = Regex.Replace(modelo, @"\s+(Desktop PC|Notebook PC)$", "", RegexOptions.IgnoreCase).Trim();

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

                string fechaInv = DateTime.Now.ToString("yyyy-MM-dd");
                if (data.ContainsKey("Fecha de Auditoria") && data["Fecha de Auditoria"].Length >= 10)
                    fechaInv = data["Fecha de Auditoria"].Substring(0, 10);

                List<string> nombresArr = new List<string>();
                List<string> correosArr = new List<string>();
                foreach (string u in users)
                {
                    string uAcc = Regex.Match(u, @"Usuario:\s*([^\[]+)").Groups[1].Value.Trim();
                    string uName = Regex.Match(u, @"Nombre:\s*([^|]+)").Groups[1].Value.Trim();
                    string uMail = Regex.Match(u, @"Correo:\s*(.+)$").Groups[1].Value.Trim();
                    string uShort = uAcc.Contains("\\") ? uAcc.Substring(uAcc.IndexOf('\\') + 1) : uAcc;

                    if (!string.IsNullOrEmpty(uName) && uName.IndexOf("Sin nombre registrado", StringComparison.OrdinalIgnoreCase) < 0)
                        nombresArr.Add(uName.ToUpper());
                    else if (!string.IsNullOrEmpty(uShort))
                        nombresArr.Add(uShort.ToUpper());

                    if (!string.IsNullOrEmpty(uMail) && uMail.IndexOf("Sin correo registrado", StringComparison.OrdinalIgnoreCase) < 0)
                        correosArr.Add(uMail.ToLower());
                }

                string usuariosFinal;
                string correosFinal;
                if ((pestanaDestino == "AULAS" || pestanaDestino == "LABORATORIO") && nombresArr.Count == 0)
                {
                    usuariosFinal = "DOCENTE";
                    correosFinal = "";
                }
                else
                {
                    usuariosFinal = string.Join("/", nombresArr.Distinct().ToArray());
                    correosFinal = string.Join("/", correosArr.Distinct().ToArray());
                }

                string hpInsights = CalcHpInsights(marca);
                string obs = marca == "LENOVO" ? "LENOVO SIN INSIGHT" : "NINGUNA";
                if (string.Join(" ", lines).IndexOf("validar presencialmente", StringComparison.OrdinalIgnoreCase) >= 0)
                    obs = obs == "NINGUNA" ? "VALIDAR DATOS PRESENCIALMENTE" : obs + " / VALIDAR DATOS PRESENCIALMENTE";

                DataRow row = tableTodos.NewRow();
                object[] vals = new object[] {
                    tipo, piso, "OPERATIVO", marca, modelo, serie, cpu, ram, discoDuro,
                    macPrincipal, hostName, monModelo, monSerie, area, remachado, aulaLabAdm,
                    fechaInv, orgActual, "S\u00CD", usuariosFinal, correosFinal, "S\u00CD", hpInsights,
                    "", "", tecnicosResponsables, obs, pestanaDestino
                };
                row.ItemArray = vals;
                tableTodos.Rows.Add(row);
            }

            // Se engancha despues de la carga: solo reacciona a ediciones posteriores de MARCA
            tableTodos.ColumnChanged += TableTodos_ColumnChanged;

            ApplyGridFilter();
            UpdateTxtCounterBadge();
        }

        // Regla de negocio: HP INSIGHTS = "SI" solo para equipos HP; cualquier otra marca = "NO"
        private static string CalcHpInsights(string marca)
        {
            string m = (marca ?? "").Trim().ToUpperInvariant();
            bool esHp = Regex.IsMatch(m, @"\bHP\b") || m.Contains("HEWLETT");
            return esHp ? "S\u00CD" : "NO";
        }

        // Recalcula HP INSIGHTS cuando se edita la MARCA de cualquier fila (manual o cargada desde .txt)
        private void TableTodos_ColumnChanged(object sender, DataColumnChangeEventArgs e)
        {
            if (e.Column == null || e.Column.ColumnName != "MARCA") return;
            string nuevo = CalcHpInsights(e.ProposedValue != null ? e.ProposedValue.ToString() : "");
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
            r["ANTIVIRUS"] = "S\u00CD";
            r["ABSOLUTE"] = "S\u00CD";
            r["HP INSIGHTS"] = CalcHpInsights(Convert.ToString(r["MARCA"]));
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

            DialogResult open = MessageBox.Show(
                string.Format("Archivo Excel generado exitosamente en:\n{0}\n\n- ADMINISTRATIVOS: {1}\n- AULAS: {2}\n- LABORATORIO: {3}\n\n\u00BFDeseas abrir el archivo Excel ahora?", xlsxPath, rowsAdm.Count, rowsAu.Count, rowsLab.Count),
                "Excel Generado", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
            if (open == DialogResult.Yes)
                Process.Start(xlsxPath);
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
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        // Punto de entrada cuando se compila como InventarioTI.exe (Compilar_Exe.bat).
        // Iniciar_Inventario.bat no usa Main: llama a StartApp() directamente via Add-Type.
        [STAThread]
        public static void Main()
        {
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