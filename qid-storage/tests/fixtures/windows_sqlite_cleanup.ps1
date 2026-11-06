# Temporary, opt-in helper for windows-sqlite-cleanup-diagnostic.yml only.
# The parent test bounds this entire process, suppresses stderr, and still makes
# its original first deletion assertion even if this snapshot fails or times out.
param([string]$Database)
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
    static string[] Query(string path, string suffix) {
        uint session;
        Check(RmStartSession(out session, 0, new StringBuilder(33)) == 0);
        try {
            // One session per exact resource identifies the matched suffix;
            // never register a directory, prefix, wildcard, process or service.
            Check(RmRegisterResources(session, 1, new[] { path }, 0,
                IntPtr.Zero, 0, IntPtr.Zero) == 0);
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
    public static string[] Capture(string database) {
        Check(Path.IsPathFullyQualified(database));
        var rows = new List<string>();
        foreach (string suffix in new[] { "", "-wal", "-shm", "-journal" })
            rows.AddRange(Query(database + suffix, suffix == "" ? "db" : suffix));
        return rows.ToArray();
    }
}
'@
    # Emit only after every exact-resource query and session shutdown succeeded.
    # No full paths, command lines, app/service labels or raw exceptions escape.
    $rows = [QidCleanupOwners]::Capture($Database)
    foreach ($row in $rows) { Write-Host $row }
    Write-Host 'RM snapshot complete (not an exhaustive handle trace).'
    exit 0
} catch {
    Write-Host 'ERROR: Restart Manager snapshot untrusted (raw exception suppressed).'
    exit 1
}
