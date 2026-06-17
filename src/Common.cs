// Ver.1.0 by JA1XPM
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace DsxCli;

internal static class Proto
{
    public const byte FrameEnd = 0x7E;
    public const byte FrameEsc = 0x7D;
    public const byte EscXor = 0x20;
    public const byte Meta = 0x01;
    public const byte Data = 0x02;
    public const byte WindowEnd = 0x03;
    public const byte Done = 0x04;
    public const byte AckMeta = 0x81;
    public const byte AckWindow = 0x82;
    public const byte AckDone = 0x83;
    private const int HeaderSize = 12;

    public static byte[] MakeFrame(byte type, uint session, uint seq = 0, byte flags = 0, byte[]? payload = null)
    {
        payload ??= Array.Empty<byte>();
        var body = new byte[HeaderSize + payload.Length + 4];
        body[0] = type;
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(1), session);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(5), seq);
        body[9] = flags;
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(10), checked((ushort)payload.Length));
        payload.CopyTo(body.AsSpan(HeaderSize));
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(HeaderSize + payload.Length), Crc32.Compute(body.AsSpan(0, HeaderSize + payload.Length)));

        var escaped = new List<byte>(body.Length + 8) { FrameEnd };
        foreach (var b in body)
        {
            if (b is FrameEnd or FrameEsc or 0x11 or 0x13)
            {
                escaped.Add(FrameEsc);
                escaped.Add((byte)(b ^ EscXor));
            }
            else
            {
                escaped.Add(b);
            }
        }
        escaped.Add(FrameEnd);
        return escaped.ToArray();
    }

    public static bool TryParseFrame(byte[] escapedBody, out Frame frame)
    {
        frame = default;
        var raw = new List<byte>(escapedBody.Length);
        var esc = false;
        foreach (var b in escapedBody)
        {
            if (esc)
            {
                raw.Add((byte)(b ^ EscXor));
                esc = false;
            }
            else if (b == FrameEsc)
            {
                esc = true;
            }
            else
            {
                raw.Add(b);
            }
        }
        if (esc || raw.Count < HeaderSize + 4) return false;

        var all = raw.ToArray();
        var dataLen = all.Length - 4;
        var gotCrc = BinaryPrimitives.ReadUInt32LittleEndian(all.AsSpan(dataLen));
        if (gotCrc != Crc32.Compute(all.AsSpan(0, dataLen))) return false;

        var payloadLen = BinaryPrimitives.ReadUInt16LittleEndian(all.AsSpan(10));
        if (payloadLen != dataLen - HeaderSize) return false;
        var payload = new byte[payloadLen];
        all.AsSpan(HeaderSize, payloadLen).CopyTo(payload);
        frame = new Frame(
            all[0],
            BinaryPrimitives.ReadUInt32LittleEndian(all.AsSpan(1)),
            BinaryPrimitives.ReadUInt32LittleEndian(all.AsSpan(5)),
            all[9],
            payload);
        return true;
    }

    public static Frame? ReadFrame(SerialPortWin port, int timeoutMs)
    {
        var sw = Stopwatch.StartNew();
        var body = new List<byte>(1024);
        while (timeoutMs < 0 || sw.ElapsedMilliseconds < timeoutMs)
        {
            var b = port.ReadByte();
            if (b < 0) continue;
            if (b == FrameEnd)
            {
                if (body.Count == 0) continue;
                var bytes = body.ToArray();
                body.Clear();
                return TryParseFrame(bytes, out var frame) ? frame : null;
            }
            body.Add((byte)b);
            if (body.Count > 8192) body.Clear();
        }
        return null;
    }

    public static double SafeWireLimit(int baud) => Math.Min((baud / 10.0) * 0.85, 420.0);

    public static double MaxWireLimit(int baud) => Math.Max(SafeWireLimit(baud), (baud / 10.0) * 0.92);
}

internal readonly record struct Frame(byte Type, uint Session, uint Seq, byte Flags, byte[] Payload);

internal static class Tools
{
    public static string Find7Zip()
    {
        var candidates = new[]
        {
            Environment.GetEnvironmentVariable("DSX_7Z"),
            @"C:\Program Files\7-Zip\7z.exe",
            @"C:\Program Files (x86)\7-Zip\7z.exe",
            "7z.exe",
        };
        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate)) continue;
            if (File.Exists(candidate)) return candidate;
            var path = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (var dir in path.Split(Path.PathSeparator))
            {
                if (string.IsNullOrWhiteSpace(dir)) continue;
                var full = Path.Combine(dir, candidate);
                if (File.Exists(full)) return full;
            }
        }
        throw new FileNotFoundException("7z.exe was not found. Set DSX_7Z or install 7-Zip.");
    }

    public static TimeSpan Run7Zip(string workingDirectory, params string[] arguments)
    {
        var exe = Find7Zip();
        var psi = new ProcessStartInfo(exe)
        {
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var arg in arguments) psi.ArgumentList.Add(arg);

        var sw = Stopwatch.StartNew();
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("failed to start 7z.exe");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        sw.Stop();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"7z.exe failed with exit code {process.ExitCode}\n{stdout}\n{stderr}");
        }
        return sw.Elapsed;
    }

    public static byte[] Sha256File(string path)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(path);
        return sha.ComputeHash(fs);
    }

    public static string Hex(byte[] bytes) => Convert.ToHexString(bytes);
}

internal static class Crc32
{
    private static readonly uint[] Table = BuildTable();

    public static uint Compute(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in data) crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        return ~crc;
    }

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < table.Length; i++)
        {
            var c = i;
            for (var j = 0; j < 8; j++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        return table;
    }
}

internal sealed class RateLimiter
{
    private readonly Stopwatch sw = Stopwatch.StartNew();
    private double nextSeconds;

    public RateLimiter(double bytesPerSecond) => BytesPerSecond = Math.Max(1.0, bytesPerSecond);

    public double BytesPerSecond { get; private set; }

    public void SetBytesPerSecond(double bytesPerSecond)
    {
        BytesPerSecond = Math.Max(1.0, bytesPerSecond);
        if (nextSeconds < sw.Elapsed.TotalSeconds) nextSeconds = sw.Elapsed.TotalSeconds;
    }

    public void Wait(int byteCount)
    {
        nextSeconds += byteCount / BytesPerSecond;
        var delay = nextSeconds - sw.Elapsed.TotalSeconds;
        if (delay > 0) Thread.Sleep(TimeSpan.FromSeconds(delay));
        else if (delay < -2) nextSeconds = sw.Elapsed.TotalSeconds;
    }
}

internal sealed class SerialPortWin : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint OpenExisting = 3;
    private readonly SafeFileHandle handle;
    private readonly FileStream stream;

    public SerialPortWin(string portName, int baud)
    {
        var name = portName.StartsWith(@"\\.\", StringComparison.Ordinal) ? portName : @"\\.\" + portName;
        handle = CreateFile(name, GenericRead | GenericWrite, 0, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (handle.IsInvalid) throw new IOException($"failed to open {portName}: {Marshal.GetLastWin32Error()}");
        Configure(baud);
        stream = new FileStream(handle, FileAccess.ReadWrite, 4096, false);
    }

    public int ReadByte()
    {
        Span<byte> b = stackalloc byte[1];
        var n = stream.Read(b);
        return n == 0 ? -1 : b[0];
    }

    public void Write(byte[] data) => stream.Write(data, 0, data.Length);

    public void Dispose()
    {
        stream.Dispose();
        handle.Dispose();
    }

    private void Configure(int baud)
    {
        var dcb = new Dcb { DCBlength = (uint)Marshal.SizeOf<Dcb>() };
        if (!GetCommState(handle, ref dcb)) throw new IOException($"GetCommState failed: {Marshal.GetLastWin32Error()}");
        dcb.BaudRate = (uint)baud;
        dcb.Flags = 0x00001011;
        dcb.ByteSize = 8;
        dcb.Parity = 0;
        dcb.StopBits = 0;
        dcb.XonChar = 0x11;
        dcb.XoffChar = 0x13;
        if (!SetCommState(handle, ref dcb)) throw new IOException($"SetCommState failed: {Marshal.GetLastWin32Error()}");

        var timeouts = new CommTimeouts
        {
            ReadIntervalTimeout = 50,
            ReadTotalTimeoutMultiplier = 0,
            ReadTotalTimeoutConstant = 100,
            WriteTotalTimeoutMultiplier = 0,
            WriteTotalTimeoutConstant = 5000,
        };
        if (!SetCommTimeouts(handle, ref timeouts)) throw new IOException($"SetCommTimeouts failed: {Marshal.GetLastWin32Error()}");
        SetupComm(handle, 65536, 65536);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Dcb
    {
        public uint DCBlength;
        public uint BaudRate;
        public uint Flags;
        public ushort wReserved;
        public ushort XonLim;
        public ushort XoffLim;
        public byte ByteSize;
        public byte Parity;
        public byte StopBits;
        public byte XonChar;
        public byte XoffChar;
        public byte ErrorChar;
        public byte EofChar;
        public byte EvtChar;
        public ushort wReserved1;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CommTimeouts
    {
        public uint ReadIntervalTimeout;
        public uint ReadTotalTimeoutMultiplier;
        public uint ReadTotalTimeoutConstant;
        public uint WriteTotalTimeoutMultiplier;
        public uint WriteTotalTimeoutConstant;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetCommState(SafeFileHandle file, ref Dcb dcb);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetCommState(SafeFileHandle file, ref Dcb dcb);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetCommTimeouts(SafeFileHandle file, ref CommTimeouts timeouts);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetupComm(SafeFileHandle file, uint inQueue, uint outQueue);
}
