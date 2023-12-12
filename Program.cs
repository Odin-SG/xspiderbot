using System;
using System.Collections.Generic;
using System.Text;
using System.Data.SQLite;
using System.Text.RegularExpressions;
using System.Threading;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Drawing;
using Renci.SshNet;
using System.Security.Cryptography;

namespace xspiderbot
{
    class Program
    {
        private Cursor cursor { get; set; }
        private Process xspider { get; set; }
        private string path { get; set; }
        private string passwd { get; set; }
        private int time { get; set; }
        private int timebeforedownl { get; set; }
        private int textoffsety { get; set; }
        private int buttonoffsety { get; set; }
        private int textoffsetx { get; set; }
        private int buttonoffsetx { get; set; }
        private string sshserver { get; set; }
        private string sshlogin { get; set; }
        private string sshpwd { get; set; }
        private List<string> vulners { get; set; }
        private string[,] vulnData { get; set; }
        private string pathtovdb { get; set; }
        private string remotepath { get; set; }
        private string hash { get; set; }
        private bool isDifferent = false;
        [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint cButtons, uint dwExtraInfo);


        static void Main() {
            Program program = new Program();
            program.Start();
        }

        public int Start() {
            this.xspider = new Process();
            int matches = this.Settings();
            try
            {
                this.xspider.StartInfo.FileName = this.path;
                this.xspider.Start();
            } catch (Exception e) {
                MessageBox.Show(e.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
            }
            this.Login();
            this.GetHashFile();
            this.isDifferent = true;
            if (this.isDifferent == true)
            {
                this.GetFromDataBase();
                this.GenerateJSON();
                this.SendingBySSH();
            }
            return 0;
        }

        private int Settings() {
            try
            {
                foreach (string line in File.ReadLines("settings.cfg")) {
                    string pattern = @"\[(\w+)\]\s*?=\s*?""(.+)""";
                    Match match = Regex.Match(line, pattern);
                    if (match.Groups[1].Value == "path") {
                        this.path = match.Groups[2].Value;
                    }
                    if (match.Groups[1].Value == "pathvdb")
                    {
                        this.pathtovdb = match.Groups[2].Value;
                    }
                    if (match.Groups[1].Value == "passwd") {
                        this.passwd = match.Groups[2].Value;
                    }
                    if (match.Groups[1].Value == "time") {
                        this.time = int.Parse(match.Groups[2].Value);
                    }
                    if (match.Groups[1].Value == "textoffsety")
                    {
                        this.textoffsety = int.Parse(match.Groups[2].Value);
                    }
                    if (match.Groups[1].Value == "buttonoffsety")
                    {
                        this.buttonoffsety = int.Parse(match.Groups[2].Value);
                    }
                    if (match.Groups[1].Value == "textoffsetx")
                    {
                        this.textoffsetx = int.Parse(match.Groups[2].Value);
                    }
                    if (match.Groups[1].Value == "buttonoffsetx")
                    {
                        this.buttonoffsetx = int.Parse(match.Groups[2].Value);
                    }
                    if (match.Groups[1].Value == "path")
                    {
                        this.path = match.Groups[2].Value;
                    }
                    if (match.Groups[1].Value == "sshserver")
                    {
                        this.sshserver = match.Groups[2].Value;
                    }
                    if (match.Groups[1].Value == "sshlogin")
                    {
                        this.sshlogin = match.Groups[2].Value;
                    }
                    if (match.Groups[1].Value == "sshpwd")
                    {
                        this.sshpwd = match.Groups[2].Value;
                    }
                    if (match.Groups[1].Value == "remotepath")
                    {
                        this.remotepath = match.Groups[2].Value;
                    }
                    if (match.Groups[1].Value == "hash")
                    {
                        this.hash = match.Groups[2].Value;
                    }
                    if (match.Groups[1].Value == "timebeforedownl")
                    {
                        this.timebeforedownl = int.Parse(match.Groups[2].Value);
                    }
                }
                return 1;
            } catch (Exception e) {
                MessageBox.Show(e.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
                return 0;
            }
        }

        private void Login() {
            Thread.Sleep(this.time);
            Cursor.Position = new Point(SystemInformation.PrimaryMonitorSize.Width / 2 + this.textoffsetx, SystemInformation.PrimaryMonitorSize.Height / 2 + this.textoffsety);
            mouse_event(0x02 | 0x04, 0, 0, 0, 0);
            SendKeys.SendWait(this.passwd);
            Cursor.Position = new Point(SystemInformation.PrimaryMonitorSize.Width / 2 + this.buttonoffsetx, SystemInformation.PrimaryMonitorSize.Height / 2 + this.buttonoffsety);
            mouse_event(0x02 | 0x04, 0, 0, 0, 0);
            Thread.Sleep(this.timebeforedownl);
            this.xspider.Kill();
            this.xspider.Close();
        }

        private void GetFromDataBase() {
            this.vulners = new List<string>();
            try
            {
                SQLiteConnection dbfile = new SQLiteConnection("Data Source="+ pathtovdb + "; Version=3;");
                dbfile.Open();
                SQLiteCommand dbquery = dbfile.CreateCommand();
                dbquery.CommandText = "SELECT count(vulner) FROM vulner_data";
                int lenData = Convert.ToInt32(dbquery.ExecuteScalar());

                dbquery.CommandText = "SELECT * FROM vulner_data ORDER BY vulner DESC";
                SQLiteDataReader result = dbquery.ExecuteReader();
                byte[] resBytes = new byte[10000];
                byte[] linksBytes = new byte[255];
                this.vulnData = new string[lenData / 3, 4];
                int counter = -1;

                while (result.Read()) {
                    if (counter >= 0) {
                        if (result[1].ToString() == "3") {
                            continue;
                        }
                        if (Convert.ToInt32(this.vulnData[counter, 0]) == Convert.ToInt32(result[0])) {
                            counter--;
                        }
                    }
                    counter++;
                    resBytes = (byte[])result[2];
                    linksBytes = (byte[])result[4];
                    if (resBytes.Length < 10) {
                        counter--;
                        continue;
                    }
                    this.vulnData[counter, 0] = result[0].ToString();
                    if (result[1].ToString() == "1") {
                        this.vulnData[counter, 1] = Encoding.UTF8.GetString(resBytes).Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\0", "").Replace("\t", "\\t");
                    }
                    if (result[1].ToString() == "2") {
                        this.vulnData[counter, 2] = Encoding.UTF8.GetString(resBytes).Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\0", "").Replace("\t", "\\t");
                    }
                    this.vulnData[counter, 3] = Encoding.UTF8.GetString(linksBytes).Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\0", "").Replace("\t", "\\t");
                }
            } catch (Exception e) {
                MessageBox.Show(e.Message+ "\r\n\r\n" + e.StackTrace, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
            }
        }

        private bool GenerateJSON() {
            try {
                StreamWriter write = new StreamWriter("xspider.json");
                string stringLine = "{";
                write.WriteLine(stringLine);
                bool trigerStart = true;
                for (int iter = 0; iter < this.vulnData.GetLength(0); iter++) {
                    if (this.vulnData[iter, 1] != null)
                    {
                        if (trigerStart == true)
                        {
                            stringLine = "\"" + iter + "\" : { \"id\" : \"" + this.vulnData[iter, 0] + "\", \"desc_ru\" : \"" + this.vulnData[iter, 1] + "\", \"desc_en\" : \"" + this.vulnData[iter, 2] + "\", \"refs\" : \"" + this.vulnData[iter, 3] + "\" }";
                            trigerStart = false;
                        }
                        else
                        {
                            stringLine = ",\"" + iter + "\" : { \"id\" : \"" + this.vulnData[iter, 0] + "\", \"desc_ru\" : \"" + this.vulnData[iter, 1] + "\", \"desc_en\" : \"" + this.vulnData[iter, 2] + "\", \"refs\" : \"" + this.vulnData[iter, 3] + "\" }";
                        }
                        write.WriteLine(stringLine);
                    }
                }
                write.WriteLine("}");
                write.Flush();
                write.Close();
                return true;
            } catch (Exception e){
                MessageBox.Show(e.Message + "\r\n\r\n" + e.StackTrace, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
                return false;
            }
        }

        private bool SendingBySSH() {
            try
            {
				using (ScpClient scp = new ScpClient(this.sshserver, this.sshlogin, this.sshpwd))
				{
					scp.Connect();
					scp.Upload(new FileInfo("xspider.json"), this.remotepath);
					scp.Disconnect();
				};
			}
            catch (Exception e) {
                MessageBox.Show(e.Message + "\r\n\r\n" + e.StackTrace, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
                return false;
            }
            return true;
        }

        private void GetHashFile() {
            byte[] hash;
            string currHash;
            try
            {
                using (MD5 md5 = MD5.Create())
                {
                    using (Stream stream = File.OpenRead(this.pathtovdb))
                    {
                        hash = md5.ComputeHash(stream);
                        StringBuilder bytetostr = new StringBuilder();
                        for (int i = 0; i < hash.Length; i++)
                        {
                            bytetostr.Append(hash[i].ToString("x2"));
                        }
                        currHash = bytetostr.ToString();
                        if (this.hash != currHash)
                        {
                            this.isDifferent = true;
                            string text = File.ReadAllText("settings.cfg");
                            string pattern = @"\[(hash)\]\s*?=\s*?""(.+)""";
                            string replaced = Regex.Replace(text, pattern, "[$1] = \"" + currHash + "\"");
                            File.WriteAllText("settings.cfg", replaced);
                        }
                    }
                }
            }
            catch (Exception e) {
                MessageBox.Show(e.Message + "\r\n\r\n" + e.StackTrace, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
            }
        }
    }
}
