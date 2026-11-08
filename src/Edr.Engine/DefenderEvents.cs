using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Engine;

internal sealed class DefenderEvents(Context ctx)
{
    public JsonObject? Status { get; private set; }

    public void Handle(EventRecord r)
    {
        var proc = r["Process Name"];
        var path = r["Path"];
        switch (r.Id)
        {
            case 1116:
            {
                var threatId = r["Threat ID"];
                if (Detection.DefenderExcluded(ctx.Excl["defender"], ctx.Excl["realtime"], threatId, path)) return;
                var sevName = r["Severity Name"];
                var sev = Ps.Match(sevName, "Severe") ? "Critical" : Ps.Match(sevName, "High") ? "High" : "Medium";
                ctx.Event("defender", sev, $"Defender detected malware: {r["Threat Name"]}", proc, path,
                          new() { ["kind"] = "malware", ["threat"] = r["Threat Name"], ["threatId"] = threatId });
                var seen = ctx.State.Seen("defSeen");
                seen.Add($"{r["Threat Name"]}|{r.Time:yyyy-MM-dd HH:mm}");
                ctx.State.SetSeen("defSeen", seen, 2000);
                ctx.State.Save();
                break;
            }
            case 1121:
            {
                var id = r["ID"].ToLowerInvariant();
                ctx.Event("defender", "Medium", $"Defender ASR blocked: {Defender.AsrNames.GetValueOrDefault(id, id)}", proc, path, new() { ["kind"] = "asr", ["asrId"] = id, ["path"] = path });
                break;
            }
            case 1123:
                ctx.Event("defender", "Medium", "Controlled folder access blocked a write", proc, $"Tried to change: {path}", new() { ["kind"] = "cfa", ["path"] = path });
                break;
            case 1122:
            {
                var id = r["ID"].ToLowerInvariant();
                if (Defender.AlwaysAudit.Contains(id)) return;
                ctx.Event("defender", "Low", $"Defender ASR would have blocked: {Defender.AsrNames.GetValueOrDefault(id, id)}", proc, path, new() { ["kind"] = "asr-audit", ["asrId"] = id, ["path"] = path });
                break;
            }
            case 1124:
                ctx.Event("defender", "Low", "Controlled folder access would have blocked a write", proc, $"Tried to change: {path}", new() { ["kind"] = "cfa-audit", ["path"] = path });
                break;
        }
    }

    public void UpdateStatus() => Status = Defender.Status();
}
