// Ver.1.0 by JA1XPM
using System.Buffers.Binary;
using System.Security.Cryptography;
using DsxCli;

static int Usage()
{
    Console.WriteLine("usage: dsx_recv.exe COMn baud");
    return 2;
}

static string SafeOutputPath(string name)
{
    var baseName = Path.GetFileName(name.Replace('\\', '/'));
    if (string.IsNullOrWhiteSpace(baseName) || baseName is "." or "..") baseName = "received.bin";
    var candidate = baseName;
    var stem = Path.GetFileNameWithoutExtension(baseName);
    var ext = Path.GetExtension(baseName);
    var index = 1;
    while (File.Exists(candidate) || File.Exists(candidate + ".part"))
    {
        candidate = $"{stem}.recv{index}{ext}";
        index++;
    }
    return candidate;
}

static void AckWindow(SerialPortWin port, uint session, uint firstSeq, int count, IReadOnlyList<uint> missing)
{
    var payload = new byte[8 + missing.Count * 4];
    BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(0), firstSeq);
    BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(4), (ushort)count);
    BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(6), (ushort)missing.Count);
    for (var i = 0; i < missing.Count; i++) BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(8 + i * 4), missing[i]);
    port.Write(Proto.MakeFrame(Proto.AckWindow, session, payload: payload));
}

if (args.Length != 2) return Usage();
var portName = args[0];
if (!int.TryParse(args[1], out var baud)) return Usage();

uint? session = null;
string? outPath = null;
string? partPath = null;
ulong expectedSize = 0;
byte[]? expectedHash = null;
var received = new Dictionary<uint, byte[]>();
uint nextSeq = 0;
ulong written = 0;
FileStream? output = null;
using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

using var port = new SerialPortWin(portName, baud);
Console.WriteLine("waiting for sender...");
while (true)
{
    var frame = Proto.ReadFrame(port, -1);
    if (frame is null) continue;

    if (frame.Value.Type == Proto.Meta)
    {
        if (frame.Value.Payload.Length < 42) continue;
        var nameLen = BinaryPrimitives.ReadUInt16LittleEndian(frame.Value.Payload.AsSpan(0));
        expectedSize = BinaryPrimitives.ReadUInt64LittleEndian(frame.Value.Payload.AsSpan(2));
        expectedHash = frame.Value.Payload.AsSpan(10, 32).ToArray();
        if (frame.Value.Payload.Length < 42 + nameLen) continue;
        var fileName = System.Text.Encoding.UTF8.GetString(frame.Value.Payload.AsSpan(42, nameLen));
        if (session is null)
        {
            session = frame.Value.Session;
            outPath = SafeOutputPath(fileName);
            partPath = outPath + ".part";
            output = File.Create(partPath);
            Console.WriteLine($"receiving {fileName} -> {outPath} ({expectedSize} bytes)");
            Console.WriteLine($"sha256={Tools.Hex(expectedHash)}");
        }
        if (frame.Value.Session == session.Value) port.Write(Proto.MakeFrame(Proto.AckMeta, session.Value));
        continue;
    }

    if (session is null || frame.Value.Session != session.Value) continue;

    if (frame.Value.Type == Proto.Data)
    {
        if (frame.Value.Seq >= nextSeq) received[frame.Value.Seq] = frame.Value.Payload;
        continue;
    }

    if (frame.Value.Type == Proto.WindowEnd)
    {
        if (frame.Value.Payload.Length < 8) continue;
        var firstSeq = BinaryPrimitives.ReadUInt32LittleEndian(frame.Value.Payload.AsSpan(0));
        var count = BinaryPrimitives.ReadUInt16LittleEndian(frame.Value.Payload.AsSpan(4));
        if (firstSeq < nextSeq)
        {
            AckWindow(port, session.Value, firstSeq, count, Array.Empty<uint>());
            continue;
        }
        var missing = new List<uint>();
        for (uint s = firstSeq; s < firstSeq + count; s++) if (!received.ContainsKey(s)) missing.Add(s);
        if (missing.Count > 0)
        {
            AckWindow(port, session.Value, firstSeq, count, missing);
            continue;
        }
        if (firstSeq != nextSeq)
        {
            var all = new List<uint>();
            for (uint s = firstSeq; s < firstSeq + count; s++) all.Add(s);
            AckWindow(port, session.Value, firstSeq, count, all);
            continue;
        }
        for (uint s = firstSeq; s < firstSeq + count; s++)
        {
            var data = received[s];
            received.Remove(s);
            output!.Write(data, 0, data.Length);
            hasher.AppendData(data);
            written += (uint)data.Length;
            nextSeq++;
        }
        output!.Flush();
        AckWindow(port, session.Value, firstSeq, count, Array.Empty<uint>());
        var pct = expectedSize == 0 ? 100.0 : written * 100.0 / expectedSize;
        Console.WriteLine($"{written}/{expectedSize} bytes {pct,5:0.0}%");
        continue;
    }

    if (frame.Value.Type == Proto.Done)
    {
        if (output is null || expectedHash is null || partPath is null || outPath is null) continue;
        output.Flush();
        output.Dispose();
        output = null;
        var actualHash = hasher.GetHashAndReset();
        var ok = written == expectedSize && actualHash.SequenceEqual(expectedHash);
        port.Write(Proto.MakeFrame(Proto.AckDone, session.Value, flags: ok ? (byte)0 : (byte)1));
        if (!ok)
        {
            Console.Error.WriteLine("received file did not match size or SHA-256");
            Console.Error.WriteLine($"kept partial file: {partPath}");
            return 1;
        }
        File.Move(partPath, outPath);
        Console.WriteLine($"done: {outPath}");
        return 0;
    }
}
