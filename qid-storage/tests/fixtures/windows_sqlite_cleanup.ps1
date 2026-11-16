# Temporary, opt-in helper for windows-sqlite-cleanup-diagnostic.yml only.
# The parent test bounds this entire process, suppresses stderr, and still makes
# its original first deletion assertion even if this snapshot fails or times out.
# -Preflight validates Restart Manager setup only; it never enumerates owners.
# Handle is optional, read-only and restricted to the two observed library DBs.
param([string]$Database, [uint32]$TestProcessId, [string]$TestThread, [switch]$Preflight)
$ErrorActionPreference = 'Stop'
try {
    Add-Type -WarningAction SilentlyContinue -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Text.RegularExpressions;

public static class QidCleanupOwners {
    [StructLayout(LayoutKind.Sequential)]
    struct UniqueProcess {
        public uint Pid;
        public FILETIME Start;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct ProcessInfo {
        public UniqueProcess Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string AppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string ServiceName;
        public int AppType;
        public uint Status;
        public uint Session;
        [MarshalAs(UnmanagedType.Bool)] public bool Restartable;
    }
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmStartSession(out uint session, uint flags, StringBuilder key);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmRegisterResources(uint session, uint files,
        [In] string[] names, uint apps, IntPtr processes, uint services, IntPtr serviceNames);
    [DllImport("rstrtmgr.dll")]
    static extern int RmGetList(uint session, out uint needed, ref uint count,
        [In, Out] ProcessInfo[] processes, ref uint rebootReasons);
    [DllImport("rstrtmgr.dll")]
    static extern int RmEndSession(uint session);

    static void Check(bool valid) {
        if (!valid) throw new InvalidOperationException();
    }
    static string[] Query(string path, string suffix, bool preflight = false) {
        uint session;
        Check(RmStartSession(out session, 0, new StringBuilder(33)) == 0);
        try {
            // One session per exact resource identifies the matched suffix;
            // never register a directory, prefix, wildcard, process or service.
            Check(RmRegisterResources(session, 1, new[] { path }, 0,
                IntPtr.Zero, 0, IntPtr.Zero) == 0);
            // Setup-only mode still checks session shutdown in finally.
            if (preflight) return Array.Empty<string>();
            uint needed, count = 0, reboot = 0;
            int result = RmGetList(session, out needed, ref count, null, ref reboot);
            if (result == 0) {
                Check(needed == 0 && count == 0);
                return new[] { "RM suffix=" + suffix + " holders=none" };
            }
            Check(result == 234 && needed > 0); // ERROR_MORE_DATA: sizing call only.
            var processes = new ProcessInfo[needed];
            count = needed;
            // No retries: a changing/failed snapshot is not trusted evidence.
            Check(RmGetList(session, out needed, ref count, processes, ref reboot) == 0);
            Check(count <= processes.Length && needed <= processes.Length);
            var rows = new List<string>();
            for (int i = 0; i < count; i++) {
                var owner = processes[i].Process;
                using (var process = Process.GetProcessById(checked((int)owner.Pid))) {
                    long start = ((long)(uint)owner.Start.dwHighDateTime << 32)
                        | (uint)owner.Start.dwLowDateTime;
                    // A recycled PID or inaccessible/exited process invalidates
                    // the snapshot; never substitute RM's arbitrary app label.
                    Check(!process.HasExited && process.StartTime.ToUniversalTime().ToFileTimeUtc() == start);
                    string image = Path.GetFileName(process.MainModule.FileName);
                    Check(!process.HasExited && image != null &&
                        Regex.IsMatch(image, @"\A[A-Za-z0-9_.-]+\z"));
                    rows.Add("RM image=" + image + " pid=" +
                        owner.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture) + " suffix=" + suffix);
                }
            }
            if (rows.Count == 0) rows.Add("RM suffix=" + suffix + " holders=none");
            return rows.ToArray();
        } finally {
            Check(RmEndSession(session) == 0);
        }
    }
    public static void Preflight(string database) {
        Check(Path.IsPathFullyQualified(database));
        foreach (string suffix in new[] { "", "-wal", "-shm", "-journal" })
            Query(database + suffix, null, true);
    }
    public static string[] Capture(string database) {
        Check(Path.IsPathFullyQualified(database));
        var rows = new List<string>();
        foreach (string suffix in new[] { "", "-wal", "-shm", "-journal" })
            rows.AddRange(Query(database + suffix, suffix == "" ? "db" : suffix));
        return rows.ToArray();
    }
}
'@
    if ($Preflight) {
        [QidCleanupOwners]::Preflight($Database)
        exit 0
    }
    if ($TestThread -cnotmatch '\A[A-Za-z0-9_:.-]{1,128}\z') {
        throw 'Invalid test thread label'
    }
    Write-Host "RM test=$TestThread pid=$TestProcessId"
    # Emit only after every exact-resource query and session shutdown succeeded.
    # No full paths, command lines, app/service labels or raw exceptions escape.
    $rows = [QidCleanupOwners]::Capture($Database)
    foreach ($row in $rows) { Write-Host $row }
    Write-Host 'RM snapshot complete (not an exhaustive handle trace).'
    # Query live handles last, immediately before returning to the original delete.
    # Only the observed leaf allowlist gets a Handle query. No sidecars,
    # wildcard queries or system-wide scans.
    $leaf = [IO.Path]::GetFileName($Database)
    $allowlist = $env:QID_SQLITE_CLEANUP_DIAGNOSTIC_LEAF
    if ([string]::IsNullOrEmpty($allowlist) -or
        $allowlist -cnotmatch '\A[A-Za-z0-9_.,-]{1,256}\z') {
      throw 'Invalid diagnostic leaf allowlist'
    }
    if (@($allowlist -split ',') -ccontains $leaf) {
        try {
            $executable = $env:QID_SQLITE_HANDLE_EXE
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            try {
                $principal = [Security.Principal.WindowsPrincipal]::new($identity)
                if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                    throw 'Not elevated'
                }
            } finally { $identity.Dispose() }
            if ([string]::IsNullOrEmpty($executable)) { throw 'No verified executable' }
            $signature = Get-AuthenticodeSignature -LiteralPath $executable
            $subject = $signature.SignerCertificate.Subject
            if ($signature.Status -ne 'Valid' -or
                $subject -notmatch '(?:^|,\s*)CN=Microsoft Corporation(?:,|$)' -or
                $subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') {
                throw 'Signature rejected'
            }
            # Compile optional instrumentation separately: any failure here must
            # leave the existing Restart Manager capture and delete assertion intact.
            Add-Type -WarningAction SilentlyContinue -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

public static class QidCleanupHandles {
    static async System.Threading.Tasks.Task<string> ReadBounded(StreamReader reader) {
        var text = new StringBuilder();
        var buffer = new char[4096];
        int count;
        while ((count = await reader.ReadAsync(buffer, 0, buffer.Length)) != 0) {
            // Diagnostic-only output budget; overflow makes the snapshot unavailable.
            if (text.Length + count > 65536) throw new InvalidOperationException();
            text.Append(buffer, 0, count);
        }
        return text.ToString();
    }
    public static string Capture(string executable, uint pid, string database) {
        if (pid == 0 || !Path.IsPathFullyQualified(database)) throw new InvalidOperationException();
        using (var child = new Process()) {
            child.StartInfo.FileName = executable;
            child.StartInfo.UseShellExecute = false;
            child.StartInfo.CreateNoWindow = true;
            child.StartInfo.RedirectStandardOutput = true;
            child.StartInfo.RedirectStandardError = true;
            // Handle's name filter is substring-based. Restrict by PID AND the
            // full database path. PowerShell validates CSV and exact-path rows.
            foreach (string argument in new[] { "-accepteula", "-v", "-p",
                    pid.ToString(System.Globalization.CultureInfo.InvariantCulture), database })
                child.StartInfo.ArgumentList.Add(argument);
            bool started = false;
            try {
                started = child.Start();
                if (!started) throw new InvalidOperationException();
                var stdout = ReadBounded(child.StandardOutput);
                var stderr = ReadBounded(child.StandardError);
                if (!child.WaitForExit(3000)) throw new TimeoutException();
                if (!System.Threading.Tasks.Task.WaitAll(new System.Threading.Tasks.Task[] {
                        stdout, stderr }, 1000) || child.ExitCode != 0 || stderr.Result.Length != 0)
                    throw new InvalidOperationException();
                return stdout.Result; // Never write raw streams to the console or disk.
            } finally {
                if (started && !child.HasExited) {
                    child.Kill(true);
                    if (!child.WaitForExit(1000)) throw new TimeoutException();
                }
            }
        }
    }
}
'@
            $output = [QidCleanupHandles]::Capture($executable, $TestProcessId, $Database)
            $count = 0
            $lines = $output -split '\r?\n'
            if (@($lines | Where-Object { $_ -ceq 'No matching handles found.' }).Count -eq 0) {
                $headerIndex = -1
                for ($i = 0; $i -lt $lines.Length; $i++) {
                    if ($lines[$i].Replace('"', '') -ceq
                        'Process,PID,User,Handle,Type,Share Flags,Name,Access') {
                        $headerIndex = $i
                        break
                    }
                }
                if ($headerIndex -lt 0) { throw 'Unrecognized CSV' }
                $csv = $lines[$headerIndex..($lines.Length - 1)] -join "`n"
                foreach ($row in ($csv | ConvertFrom-Csv)) {
                    if ($row.PID -cne $TestProcessId.ToString() -or $row.Type -cne 'File') {
                        throw 'Unexpected row'
                    }
                    if ([string]::Equals($row.Name, $Database, [StringComparison]::OrdinalIgnoreCase)) { $count++ }
                }
            }
            Write-Host "HANDLE pid=$TestProcessId db=$leaf exact_file_matches=$count (live snapshot, not exhaustive)."
        } catch {
            Write-Host 'HANDLE unavailable (raw output suppressed).'
        }
    }
    exit 0
} catch {
    Write-Host 'ERROR: Restart Manager snapshot untrusted (raw exception suppressed).'
    exit 1
}
