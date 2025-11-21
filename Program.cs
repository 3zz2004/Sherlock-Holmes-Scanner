using System;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace SherlockHolmesScanner
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "Sherlock Holmes Scanner";
            while (true)
            {
                PrintTitle();
                PrintMenu();
                Console.Write("\nEnter your choice: ");
                string choice = Console.ReadLine()?.Trim();

                switch (choice)
                {
                    case "1": ScanSingleFile(); break;
                    case "2": ScanURL(); break;
                    case "3": ScanFolder(); break;
                    case "4": FindDuplicateFiles(); break;
                    case "5": ScanLargeFiles(); break;
                    case "6": PingTest(); break;
                    case "7": DNSCheck(); break;
                    case "8": ScanProcesses(); break;
                    case "9": CheckStartupPrograms(); break;
                    case "10": RealTimeFolderMonitor(); break;
                    case "11": ExportReports(); break;
                    case "12": AnalyzeLogs(); break;
                    case "13": WriteInfo("\nExiting… reports saved in logs.json"); return;
                    default: WriteDanger("[!] Invalid input, try again."); break;
                }

                Console.WriteLine("\nPress Enter to return to menu...");
                Console.ReadLine();
            }
        }

        // ==================== Title ====================
        static void PrintTitle()
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("Sherlock Holmes Scanner");
            Console.WriteLine("=======================");
            Console.WriteLine("Made by Eng. Ezz Eldeen\n");
            Console.ResetColor();
        }

        // ==================== Menu ====================
        static void PrintMenu()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Choose an option:");
            PrintOption("1", "Scan Single File", "Example: C:\\Users\\Ezz\\Desktop\\test.exe");
            PrintOption("2", "Scan URL", "Example: https://example.com");
            PrintOption("3", "Scan Folder", "Example: C:\\Users\\Ezz\\Downloads");
            PrintOption("4", "Find Duplicate Files", "Enter folder path to check duplicates");
            PrintOption("5", "Scan Large Files", "Enter folder path to scan large files");
            PrintOption("6", "Ping / Latency Test", "Enter host (e.g., example.com)");
            PrintOption("7", "DNS / IP Check", "Enter domain (e.g., example.com)");
            PrintOption("8", "Scan Running Processes", "Shows all active processes");
            PrintOption("9", "Check Startup Programs", "Shows programs running at startup");
            PrintOption("10", "Real-time Folder Monitor", "Enter folder path to monitor");
            PrintOption("11", "Export Reports", "Exports all saved reports");
            PrintOption("12", "Analyze Logs", "Analyzes saved logs and shows summary");
            PrintOption("13", "Exit", "");
            Console.ResetColor();
        }

        static void PrintOption(string number, string title, string example)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[{number}] {title}");
            if (!string.IsNullOrEmpty(example))
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine($"    {example}");
            }
        }

        // ==================== Visuals ====================
        static void WriteSuccess(string text) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine(text); Console.ResetColor(); }
        static void WriteWarning(string text) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine(text); Console.ResetColor(); }
        static void WriteDanger(string text) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(text); Console.ResetColor(); }
        static void WriteInfo(string text) { Console.ForegroundColor = ConsoleColor.Cyan; Console.WriteLine(text); Console.ResetColor(); }

        static void PrintBox(string title, string content, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine("╔════════════════════════════════════╗");
            Console.WriteLine($"║ {title,-34} ║");
            Console.WriteLine("╠════════════════════════════════════╣");
            foreach (var line in content.Split('\n'))
                Console.WriteLine($"║ {line,-34} ║");
            Console.WriteLine("╚════════════════════════════════════╝");
            Console.ResetColor();
        }

        // ==================== Progress Bar ====================
        static void ShowProgressBar(int durationSeconds)
        {
            int totalBlocks = 50;
            for (int i = 0; i <= totalBlocks; i++)
            {
                Console.Write("[");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write(new string('■', i));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(new string('■', totalBlocks - i));
                Console.ResetColor();
                Console.Write($"] {i * 2}%\r");
                Thread.Sleep(durationSeconds * 20); // يتحرك تدريجيًا
            }
            Console.WriteLine();
        }

        // ==================== File / Folder Scans ====================
        static void ScanSingleFile()
        {
            WriteInfo("Enter file path:");
            string path = Console.ReadLine();
            if (!File.Exists(path)) { WriteDanger("[!] File not found!"); return; }

            WriteInfo("Scanning file...");
            ShowProgressBar(2); // Loading animation
            string hash = ComputeSHA256(path);
            long size = new FileInfo(path).Length;
            string risk = EvaluateFileRisk(path, size);

            PrintBox("File Scan Result", $"Path: {path}\nSHA256: {hash}\nSize: {size} bytes\nRisk: {risk}", risk.StartsWith("HIGH") ? ConsoleColor.Red : (risk.StartsWith("MEDIUM") ? ConsoleColor.Yellow : ConsoleColor.Green));
            SaveLog(new { Type = "FileScan", File = path, SHA256 = hash, Size = size, Risk = risk });
        }

        static string ComputeSHA256(string path)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(path);
            var hash = sha.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        static string EvaluateFileRisk(string file, long size)
        {
            string ext = Path.GetExtension(file).ToLower();
            string[] dangerous = { ".exe", ".dll", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".scr" };
            if (Array.Exists(dangerous, e => e == ext)) return "HIGH - Suspicious executable";
            if (size == 0) return "MEDIUM - Empty file";
            return "LOW";
        }

        static void ScanFolder()
        {
            WriteInfo("Enter folder path:");
            string path = Console.ReadLine();
            if (!Directory.Exists(path)) { WriteDanger("[!] Folder not found!"); return; }

            string[] files = Directory.GetFiles(path);
            WriteInfo("Scanning folder...");
            ShowProgressBar(2); // Loading animation

            int dangerous = files.Count(f => new[] { ".exe", ".dll", ".js", ".vbs", ".ps1" }.Contains(Path.GetExtension(f).ToLower()));
            PrintBox("Folder Scan Result", $"Folder: {path}\nTotal Files: {files.Length}\nDangerous Files: {dangerous}", dangerous > 0 ? ConsoleColor.Red : ConsoleColor.Green);
            SaveLog(new { Type = "FolderScan", Folder = path, FileCount = files.Length, DangerousFiles = dangerous });
        }

        static void FindDuplicateFiles()
        {
            WriteInfo("Enter folder path to check duplicates:");
            string path = Console.ReadLine();
            if (!Directory.Exists(path)) { WriteDanger("[!] Folder not found!"); return; }

            var files = Directory.GetFiles(path);
            WriteInfo("Scanning for duplicates...");
            ShowProgressBar(2);

            var duplicates = files.GroupBy(f => File.ReadAllBytes(f).Length)
                                  .Where(g => g.Count() > 1)
                                  .SelectMany(g => g)
                                  .ToList();

            PrintBox("Duplicate Files", duplicates.Count > 0 ? string.Join("\n", duplicates) : "No duplicates found", duplicates.Count > 0 ? ConsoleColor.Yellow : ConsoleColor.Green);
            SaveLog(new { Type = "DuplicateFiles", Folder = path, Count = duplicates.Count });
        }

        static void ScanLargeFiles()
        {
            WriteInfo("Enter folder path:");
            string path = Console.ReadLine();
            if (!Directory.Exists(path)) { WriteDanger("[!] Folder not found!"); return; }

            WriteInfo("Scanning large files...");
            ShowProgressBar(2);

            var files = Directory.GetFiles(path);
            foreach (var file in files)
            {
                long size = new FileInfo(file).Length;
                if (size > 100 * 1024 * 1024) // >100MB
                    WriteWarning($"{file} -> {size / (1024 * 1024)} MB");
            }

            SaveLog(new { Type = "LargeFiles", Folder = path });
        }

        // ==================== URL / Network ====================
        static void ScanURL()
        {
            WriteInfo("Enter URL:");
            string url = Console.ReadLine();

            WriteInfo("Scanning URL...");
            ShowProgressBar(2);

            string status = CheckURL(url, out string server, out string agent);
            PrintBox("URL Scan Result", $"URL: {url}\nStatus: {status}\nServer: {server}\nPowered By: {agent}", status == "Safe" ? ConsoleColor.Green : ConsoleColor.Red);
            SaveLog(new { Type = "URLScan", URL = url, Status = status, Server = server, Agent = agent });
        }

        static string CheckURL(string url, out string server, out string agent)
        {
            server = "Unknown"; agent = "Unknown";
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "GET"; req.Timeout = 5000;
                using var resp = (HttpWebResponse)req.GetResponse();
                server = resp.Headers["Server"] ?? "N/A";
                agent = resp.Headers["X-Powered-By"] ?? "N/A";
                return (int)resp.StatusCode >= 400 ? "Malicious / Unreachable" : "Safe";
            }
            catch { return "Malicious / Unreachable"; }
        }

        static void PingTest()
        {
            WriteInfo("Enter host to ping:");
            string host = Console.ReadLine();

            try
            {
                var ping = new System.Net.NetworkInformation.Ping();
                var reply = ping.Send(host);
                PrintBox("Ping Result", $"Address: {host}\nStatus: {reply.Status}\nTime: {reply.RoundtripTime} ms", reply.Status == System.Net.NetworkInformation.IPStatus.Success ? ConsoleColor.Green : ConsoleColor.Red);
            }
            catch { WriteDanger("[!] Ping failed."); }
        }

        static void DNSCheck()
        {
            WriteInfo("Enter domain:");
            string host = Console.ReadLine();

            try
            {
                var ips = System.Net.Dns.GetHostAddresses(host);
                PrintBox("DNS / IP Check", string.Join("\n", ips.Select(ip => ip.ToString())), ConsoleColor.Green);
            }
            catch { WriteDanger("[!] DNS resolution failed."); }
        }

        // ==================== System / Monitoring ====================
        static void ScanProcesses()
        {
            var processes = Process.GetProcesses();
            PrintBox("Running Processes", string.Join("\n", processes.Select(p => p.ProcessName)), ConsoleColor.Green);
        }

        static void CheckStartupPrograms()
        {
            string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            var files = Directory.Exists(startup) ? Directory.GetFiles(startup) : new string[] { };
            PrintBox("Startup Programs", files.Length > 0 ? string.Join("\n", files) : "No startup programs found", ConsoleColor.Green);
        }

        static void RealTimeFolderMonitor()
        {
            WriteInfo("Enter folder to monitor:");
            string path = Console.ReadLine();
            if (!Directory.Exists(path)) { WriteDanger("[!] Folder not found!"); return; }

            WriteInfo("Monitoring folder... Press Ctrl+C to stop.");
            var watcher = new FileSystemWatcher(path);
            watcher.EnableRaisingEvents = true;
            watcher.Created += (s, e) => WriteWarning($"New file added: {e.Name}");
            Thread.Sleep(Timeout.Infinite);
        }

        // ==================== Utilities ====================
        static void ExportReports()
        {
            WriteInfo("Reports saved in logs.json");
        }

        static void AnalyzeLogs()
        {
            if (!File.Exists("logs.json")) { WriteDanger("[!] No logs found!"); return; }
            var json = File.ReadAllText("logs.json");
            var logs = JsonSerializer.Deserialize<List<object>>(json);
            PrintBox("Logs Analysis", $"Total Entries: {logs.Count}", ConsoleColor.Blue);
        }

        // ==================== Logging ====================
        static void SaveLog(object data)
        {
            string path = "logs.json";
            List<object> allLogs = new();
            if (File.Exists(path))
            {
                string json = File.ReadAllText(path);
                allLogs = JsonSerializer.Deserialize<List<object>>(json) ?? new List<object>();
            }
            allLogs.Add(data);
            File.WriteAllText(path, JsonSerializer.Serialize(allLogs, new JsonSerializerOptions { WriteIndented = true }));
        }
    }
}