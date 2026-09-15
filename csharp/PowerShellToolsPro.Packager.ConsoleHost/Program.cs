using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.PowerShell;

namespace PowerShellToolsPro.Packager.ConsoleHost;

internal class Program
{
	private static Process _console;

	public static string AssemblyDirectory
	{
		get
		{
			string codeBase = Assembly.GetExecutingAssembly().CodeBase;
			UriBuilder uriBuilder = new UriBuilder(codeBase);
			string path = Uri.UnescapeDataString(uriBuilder.Path);
			return Path.GetDirectoryName(path);
		}
	}

	[DllImport("user32.dll")]
	public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

	[DllImport("kernel32")]
	public static extern IntPtr GetConsoleWindow();

	[DllImport("Kernel32")]
	private static extern bool SetConsoleCtrlHandler(EventHandler handler, bool add);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool AttachConsole(int dwProcessId);

	[DllImport("user32.dll")]
	private static extern bool SetProcessDPIAware();

	private static int Main(string[] args)
	{
		List<string> list = new List<string>();
		foreach (string text in args)
		{
			string item = text;
			if (text.Contains(" "))
			{
				item = "'" + text + "'";
			}
			list.Add(item);
		}
		AttachConsole();
		if (false)
		{
			SetProcessDPIAware();
		}
		string tempFileName = Path.GetTempFileName();
		string text2 = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
		if (WriteResourceToFile("PreMigrate.Modules.zip", tempFileName))
		{
			ZipFile.ExtractToDirectory(tempFileName, text2);
			AddValueToPathEnvVar(text2);
		}
		string str;
		using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("PreMigrate.script.ps1"))
		{
			using StreamReader streamReader = new StreamReader(stream);
			str = streamReader.ReadToEnd();
		}
		try
		{
			string text3 = ReplaceString(str, "$PSScriptRoot", "$PoshToolsRoot", StringComparison.OrdinalIgnoreCase);
			List<string> list2 = new List<string>();
			list2.AddRange(new string[2]
			{
				"-Command",
				text3.TrimEnd('\r', '\n')
			});
			list2.AddRange(list);
			list2.AddRange(new string[2]
			{
				"-PoshToolsRoot",
				"\"" + AssemblyDirectory + "\""
			});
			return ConsoleShell.Start(RunspaceConfiguration.Create(), null, null, list2.ToArray());
		}
		finally
		{
			_console?.Kill();
			DeleteModuleDirectory(text2);
		}
	}

	public static bool WriteResourceToFile(string resourceName, string fileName)
	{
		using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
		if (stream == null)
		{
			return false;
		}
		using (FileStream destination = new FileStream(fileName, FileMode.Create, FileAccess.Write))
		{
			stream.CopyTo(destination);
		}
		return true;
	}

	public static void AddValueToPathEnvVar(string path)
	{
		string environmentVariable = Environment.GetEnvironmentVariable("PSModulePath");
		environmentVariable = environmentVariable + ";" + path;
		Environment.SetEnvironmentVariable("PSModulePath", environmentVariable);
	}

	private static void DeleteModuleDirectory(string directory)
	{
		if (Directory.Exists(directory))
		{
			Process process = new Process();
			process.StartInfo = new ProcessStartInfo();
			process.StartInfo.UseShellExecute = false;
			process.StartInfo.CreateNoWindow = true;
			process.StartInfo.FileName = "powershell";
			process.StartInfo.Arguments = "-WindowStyle Hidden -NoProfile -NonInteractive -Command \"Start-Sleep 2; Remove-Item '" + directory + "' -Force -Recurse\"";
			process.Start();
		}
	}

	public static string ReplaceString(string str, string oldValue, string newValue, StringComparison comparison)
	{
		StringBuilder stringBuilder = new StringBuilder();
		int num = 0;
		int num2;
		for (num2 = str.IndexOf(oldValue, comparison); num2 != -1; num2 = str.IndexOf(oldValue, num2, comparison))
		{
			stringBuilder.Append(str.Substring(num, num2 - num));
			stringBuilder.Append(newValue);
			num2 += oldValue.Length;
			num = num2;
		}
		stringBuilder.Append(str.Substring(num));
		return stringBuilder.ToString();
	}

	private static void AttachConsole()
	{
		if (!AttachConsole(-1))
		{
			_console = new Process();
			_console.StartInfo = new ProcessStartInfo();
			_console.StartInfo.UseShellExecute = false;
			_console.StartInfo.CreateNoWindow = true;
			_console.StartInfo.FileName = "cmd";
			_console.Start();
			bool flag = AttachConsole(_console.Id);
			int num = 0;
			while (num < 100 && !flag)
			{
				Thread.Sleep(100);
				flag = AttachConsole(_console.Id);
			}
		}
	}
}
