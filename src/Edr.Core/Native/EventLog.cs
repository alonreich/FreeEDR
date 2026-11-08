using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Xml;

namespace Edr.Core.Native;

public sealed class EventRecord
{
    public int Id { get; init; }
    public string Channel { get; set; } = "";
    public DateTime Time { get; init; }
    public Dictionary<string, string> Data { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string this[string key] => Data.TryGetValue(key, out var v) ? v : "";

    public static EventRecord? FromXml(string xml)
    {
        try
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            var ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event");
            var id = int.TryParse(doc.SelectSingleNode("/e:Event/e:System/e:EventID", ns)?.InnerText, out var i) ? i : 0;
            var t = doc.SelectSingleNode("/e:Event/e:System/e:TimeCreated/@SystemTime", ns)?.Value;
            var time = DateTime.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d.ToLocalTime() : DateTime.Now;
            var r = new EventRecord { Id = id, Time = time };
            foreach (XmlElement e in doc.SelectNodes("/e:Event/e:EventData/e:Data", ns)!)
            {
                var name = e.GetAttribute("Name");
                if (name.Length > 0) r.Data[name] = e.InnerText;
            }
            foreach (XmlElement e in doc.SelectNodes("/e:Event/e:UserData/*/*", ns)!) r.Data.TryAdd(e.LocalName, e.InnerText);
            if (doc.SelectSingleNode("/e:Event/e:System/e:Channel", ns)?.InnerText is { } ch) r.Channel = ch;
            return r;
        }
        catch (XmlException) { return null; }
    }
}

[SupportedOSPlatform("windows")]
public sealed unsafe partial class EventSubscription : IDisposable
{
    private readonly Action<string, string?> _onEvent;
    private readonly Action<int> _onError;
    private readonly nint _bookmark;
    private nint _handle;
    private GCHandle _self;

    public string Channel { get; }

    private EventSubscription(string channel, Action<string, string?> onEvent, Action<int> onError, nint bookmark)
    {
        Channel = channel;
        _onEvent = onEvent;
        _onError = onError;
        _bookmark = bookmark;
    }

    public static EventSubscription Start(string channel, string xpath, string? bookmarkXml, Action<string, string?> onEvent, Action<int> onError)
    {
        nint bm;
        uint flags;
        if (!string.IsNullOrWhiteSpace(bookmarkXml))
        {
            bm = EvtCreateBookmark(bookmarkXml);
            if (bm == 0) throw new InvalidDataException($"bookmark rejected (error {Marshal.GetLastWin32Error()})");
            flags = 3 | 0x10000;
        }
        else
        {
            bm = EvtCreateBookmark(null);
            flags = 1;
        }
        var s = new EventSubscription(channel, onEvent, onError, bm);
        s._self = GCHandle.Alloc(s);
        s._handle = EvtSubscribe(0, 0, channel, xpath, string.IsNullOrWhiteSpace(bookmarkXml) ? 0 : bm, GCHandle.ToIntPtr(s._self), &Callback, flags);
        if (s._handle == 0)
        {
            var err = Marshal.GetLastWin32Error();
            s.Dispose();
            if (!string.IsNullOrWhiteSpace(bookmarkXml) && err is 15005 or 15011 or 15012 or 13 or 87) throw new InvalidDataException($"bookmark rejected (error {err})");
            throw new IOException($"Cannot subscribe to {channel} (error {err})");
        }
        return s;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static uint Callback(int action, nint context, nint evt)
    {
        try
        {
            if (GCHandle.FromIntPtr(context).Target is not EventSubscription s) return 0;
            if (action == 0) { s._onError((int)evt); return 0; }
            var xml = Render(evt, 1);
            if (xml is null) return 0;
            string? bm = null;
            if (s._bookmark != 0 && EvtUpdateBookmark(s._bookmark, evt)) bm = Render(s._bookmark, 2);
            s._onEvent(xml, bm);
        }
        catch (Exception) { }
        return 0;
    }

    private static string? Render(nint handle, uint flags)
    {
        EvtRender(0, handle, flags, 0, null, out var used, out _);
        if (used == 0) return null;
        var buf = new char[used / 2 + 1];
        fixed (char* p = buf)
        {
            if (!EvtRender(0, handle, flags, (uint)(buf.Length * 2), p, out used, out _)) return null;
        }
        return new string(buf, 0, Math.Max(0, (int)used / 2 - 1));
    }

    public static List<EventRecord> Query(string channel, string xpathFilter, TimeSpan since)
    {
        var list = new List<EventRecord>();
        var ms = (long)since.TotalMilliseconds;
        var q = $"*[System[{xpathFilter} and TimeCreated[timediff(@SystemTime) <= {ms}]]]";
        var h = EvtQuery(0, channel, q, 1);
        if (h == 0) return list;
        try
        {
            var events = new nint[64];
            while (true)
            {
                fixed (nint* p = events)
                {
                    if (!EvtNext(h, (uint)events.Length, p, 1000, 0, out var returned) || returned == 0) break;
                    for (var i = 0; i < returned; i++)
                    {
                        var xml = Render(events[i], 1);
                        EvtClose(events[i]);
                        if (xml is not null && EventRecord.FromXml(xml) is { } r) list.Add(r);
                    }
                }
            }
        }
        finally { EvtClose(h); }
        return list.OrderBy(r => r.Time).ToList();
    }

    public void Dispose()
    {
        if (_handle != 0) { EvtClose(_handle); _handle = 0; }
        if (_bookmark != 0) EvtClose(_bookmark);
        if (_self.IsAllocated) _self.Free();
    }

    [LibraryImport("wevtapi.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint EvtSubscribe(nint session, nint signalEvent, string channelPath, string query, nint bookmark, nint context,
                                             delegate* unmanaged[Stdcall]<int, nint, nint, uint> callback, uint flags);

    [LibraryImport("wevtapi.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint EvtQuery(nint session, string path, string query, uint flags);

    [LibraryImport("wevtapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EvtNext(nint resultSet, uint eventsSize, nint* events, uint timeout, uint flags, out uint returned);

    [LibraryImport("wevtapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EvtRender(nint context, nint fragment, uint flags, uint bufferSize, char* buffer, out uint bufferUsed, out uint propertyCount);

    [LibraryImport("wevtapi.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint EvtCreateBookmark(string? bookmarkXml);

    [LibraryImport("wevtapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EvtUpdateBookmark(nint bookmark, nint evt);

    [LibraryImport("wevtapi.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EvtClose(nint handle);
}
