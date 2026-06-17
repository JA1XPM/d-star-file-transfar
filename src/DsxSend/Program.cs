// Ver.1.0 by JA1XPM
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using DsxCli;

static int Usage()
{
    Console.WriteLine("usage: dsx_send.exe COMn baud file");
    return 2;
}

static Frame? WaitFor(SerialPortWin port, uint session, byte type, int timeoutMs)
{
    var deadline = Environment.TickCount64 + timeoutMs;
    while (Environment.TickCount64 < deadline)
    {
        var frame = Proto.ReadFrame(port, 200);
        if (frame is { } f && f.Session == session && f.Type == type) return f;
    }
    return null;
}

static void SendPaced(SerialPortWin port, RateLimiter limiter, byte[] frame)
{
    port.Write(frame);
    limiter.Wait(frame.Length);
}

static List<uint>? ParseMissingAck(Frame ack, uint firstSeq, int count)
{
    if (ack.Payload.Length < 8) return null;
    var ackFirst = BinaryPrimitives.ReadUInt32LittleEndian(ack.Payload.AsSpan(0));
    var ackCount = BinaryPrimitives.ReadUInt16LittleEndian(ack.Payload.AsSpan(4));
    var missCount = BinaryPrimitives.ReadUInt16LittleEndian(ack.Payload.AsSpan(6));
    if (ackFirst != firstSeq || ackCount != count) return null;

    var missing = new List<uint>(missCount);
    for (var i = 0; i < missCount; i++)
    {
        var pos = 8 + i * 4;
        if (pos + 4 > ack.Payload.Length) return null;
        missing.Add(BinaryPrimitives.ReadUInt32LittleEndian(ack.Payload.AsSpan(pos)));
    }
    return missing;
}

static bool ConfirmRange(
    SerialPortWin port,
    RateLimiter limiter,
    uint session,
    uint firstSeq,
    IReadOnlyList<uint> seqs,
    int payloadLen,
    Dictionary<uint, byte[]> chunks)
{
    var hadLoss = false;
    while (true)
    {
        var endPayload = new byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(endPayload.AsSpan(0), firstSeq);
        BinaryPrimitives.WriteUInt16LittleEndian(endPayload.AsSpan(4), (ushort)seqs.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(endPayload.AsSpan(6), (ushort)payloadLen);
        SendPaced(port, limiter, Proto.MakeFrame(Proto.WindowEnd, session, seqs[^1], payload: endPayload));

        var ack = WaitFor(port, session, Proto.AckWindow, 5000);
        if (ack is null)
        {
            hadLoss = true;
            continue;
        }

        var missing = ParseMissingAck(ack.Value, firstSeq, seqs.Count);
        if (missing is null) continue;
        if (missing.Count == 0) return hadLoss;

        hadLoss = true;
        foreach (var missingSeq in missing)
        {
            if (chunks.TryGetValue(missingSeq, out var data))
            {
                SendPaced(port, limiter, Proto.MakeFrame(Proto.Data, session, missingSeq, payload: data));
            }
        }
    }
}

if (args.Length != 3) return Usage();
var portName = args[0];
if (!int.TryParse(args[1], out var baud)) return Usage();
var path = args[2];
if (!File.Exists(path))
{
    Console.Error.WriteLine($"file not found: {path}");
    return 2;
}

var sessionBytes = RandomNumberGenerator.GetBytes(4);
var session = BinaryPrimitives.ReadUInt32LittleEndian(sessionBytes);
var fileInfo = new FileInfo(path);
var fileNameBytes = System.Text.Encoding.UTF8.GetBytes(Path.GetFileName(path));
if (fileNameBytes.Length > ushort.MaxValue)
{
    Console.Error.WriteLine("file name is too long");
    return 2;
}

var digest = Tools.Sha256File(path);
var meta = new byte[2 + 8 + 32 + fileNameBytes.Length];
BinaryPrimitives.WriteUInt16LittleEndian(meta.AsSpan(0), (ushort)fileNameBytes.Length);
BinaryPrimitives.WriteUInt64LittleEndian(meta.AsSpan(2), (ulong)fileInfo.Length);
digest.CopyTo(meta.AsSpan(10));
fileNameBytes.CopyTo(meta.AsSpan(42));

var maxWireLimit = Proto.MaxWireLimit(baud);
var limiter = new RateLimiter(maxWireLimit);
Console.WriteLine($"session={session:X8} file={Path.GetFileName(path)} size={fileInfo.Length} bytes");
Console.WriteLine($"sha256={Tools.Hex(digest)}");
Console.WriteLine($"wire_limit={limiter.BytesPerSecond:0}-{maxWireLimit:0} bytes/s probe-then-burst");

using var port = new SerialPortWin(portName, baud);
var metaFrame = Proto.MakeFrame(Proto.Meta, session, payload: meta);
Console.WriteLine("waiting for receiver...");
while (true)
{
    SendPaced(port, limiter, metaFrame);
    if (WaitFor(port, session, Proto.AckMeta, 1500) is not null) break;
}

var payloadLen = 1024;
const int minPayload = 64;
var targetWindowBytes = 4096;
const int minWindowBytes = 4096;
const int maxWindowBytes = 32768;
uint seq = 0;
long sentBytes = 0;
var chunks = new Dictionary<uint, byte[]>();
var transferTimer = Stopwatch.StartNew();

using (var input = File.OpenRead(path))
{
    Console.WriteLine("probing...");
    while (sentBytes < fileInfo.Length)
    {
        var firstSeq = seq;
        var windowStartBytes = sentBytes;
        var windowTimer = Stopwatch.StartNew();
        var countLimit = Math.Clamp(targetWindowBytes / payloadLen, 4, 256);
        var windowSeqs = new List<uint>(countLimit);

        for (var i = 0; i < countLimit; i++)
        {
            var data = new byte[payloadLen];
            var n = input.Read(data, 0, data.Length);
            if (n <= 0) break;
            if (n != data.Length) Array.Resize(ref data, n);
            chunks[seq] = data;
            windowSeqs.Add(seq);
            SendPaced(port, limiter, Proto.MakeFrame(Proto.Data, session, seq, payload: data));
            sentBytes += data.Length;
            seq++;
        }

        if (windowSeqs.Count == 0) break;
        var windowHadLoss = ConfirmRange(port, limiter, session, firstSeq, windowSeqs, payloadLen, chunks);
        windowTimer.Stop();
        var pct = fileInfo.Length == 0 ? 100.0 : sentBytes * 100.0 / fileInfo.Length;
        var payloadRate = windowTimer.Elapsed.TotalSeconds > 0
            ? (sentBytes - windowStartBytes) / windowTimer.Elapsed.TotalSeconds
            : 0.0;
        Console.WriteLine($"{sentBytes}/{fileInfo.Length} bytes {pct,5:0.0}% probe payload={payloadLen} window={targetWindowBytes / 1024}KB pace={limiter.BytesPerSecond:0}B/s actual={payloadRate:0}B/s");

        foreach (var s in windowSeqs) chunks.Remove(s);

        if (windowHadLoss)
        {
            payloadLen = Math.Max(minPayload, payloadLen / 2);
            targetWindowBytes = Math.Max(minWindowBytes, targetWindowBytes / 2);
            limiter.SetBytesPerSecond(Math.Max(Proto.SafeWireLimit(baud), limiter.BytesPerSecond * 0.75));
            continue;
        }

        if (targetWindowBytes >= maxWindowBytes) break;
        targetWindowBytes = Math.Min(maxWindowBytes, targetWindowBytes * 2);
    }

    Console.WriteLine($"burst payload={payloadLen} pace={limiter.BytesPerSecond:0}B/s");
    const int maxBurstPackets = 4096;
    while (sentBytes < fileInfo.Length)
    {
        var firstSeq = seq;
        var burstStartBytes = sentBytes;
        var burstTimer = Stopwatch.StartNew();
        var burstSeqs = new List<uint>();
        chunks.Clear();

        for (var i = 0; i < maxBurstPackets; i++)
        {
            var data = new byte[payloadLen];
            var n = input.Read(data, 0, data.Length);
            if (n <= 0) break;
            if (n != data.Length) Array.Resize(ref data, n);
            chunks[seq] = data;
            burstSeqs.Add(seq);
            SendPaced(port, limiter, Proto.MakeFrame(Proto.Data, session, seq, payload: data));
            sentBytes += data.Length;
            seq++;
        }

        if (burstSeqs.Count == 0) break;
        var hadLoss = ConfirmRange(port, limiter, session, firstSeq, burstSeqs, payloadLen, chunks);
        burstTimer.Stop();
        var pct = fileInfo.Length == 0 ? 100.0 : sentBytes * 100.0 / fileInfo.Length;
        var payloadRate = burstTimer.Elapsed.TotalSeconds > 0
            ? (sentBytes - burstStartBytes) / burstTimer.Elapsed.TotalSeconds
            : 0.0;
        var lossText = hadLoss ? " retransmit" : "";
        Console.WriteLine($"{sentBytes}/{fileInfo.Length} bytes {pct,5:0.0}% burst count={burstSeqs.Count} actual={payloadRate:0}B/s{lossText}");
    }
}

transferTimer.Stop();
Console.WriteLine($"payload sent in {transferTimer.Elapsed.TotalSeconds:0.0}s");
Console.WriteLine("finalizing...");
var done = Proto.MakeFrame(Proto.Done, session);
for (var i = 0; i < 20; i++)
{
    SendPaced(port, limiter, done);
    var ack = WaitFor(port, session, Proto.AckDone, 1500);
    if (ack is null) continue;
    if (ack.Value.Flags != 0)
    {
        Console.Error.WriteLine("receiver reported final SHA-256/size mismatch");
        return 1;
    }
    Console.WriteLine("done");
    return 0;
}
Console.Error.WriteLine("sent, but final ACK was not received");
return 1;
