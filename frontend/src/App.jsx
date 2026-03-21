import { useState, useRef, useEffect } from "react";

const API = "http://localhost:5000";

const SKILLS = [
  { id:"lhf-toolkit",           label:"LHF",         color:"#0ea5e9", endpoint:"/scan/lhf",    desc:"Headers · DNS · CORS · Info Disclosure" },
  { id:"recon-dominator",       label:"Recon",        color:"#7c3aed", endpoint:"/scan/recon",  desc:"Subdomain enum · Port scan · OSINT" },
  { id:"webapp-exploit-hunter", label:"WebApp",       color:"#f97316", endpoint:"/scan/webapp", desc:"SQLi · XSS · SSRF · IDOR · SSTI" },
  { id:"api-breaker",           label:"API",          color:"#ec4899", endpoint:"/scan/api",    desc:"BOLA · JWT · GraphQL · Mass Assignment" },
  { id:"cloud-pivot-finder",    label:"Cloud",        color:"#14b8a6", endpoint:"/scan/cloud",  desc:"S3 · Takeover · CI/CD · Serverless" },
  { id:"attack-path-architect", label:"Attack Path",  color:"#f59e0b", endpoint:null,           desc:"MITRE ATT&CK · Kill Chains" },
  { id:"vuln-chain-composer",   label:"Chain",        color:"#ef4444", endpoint:null,           desc:"Exploit Chains · Bug Bounty Reports" },
];

const SEV = { CRITICAL:"#ef4444", HIGH:"#f97316", MEDIUM:"#f59e0b", LOW:"#3b82f6", INFO:"#6b7280" };

const css = `
  @keyframes bounce{0%,80%,100%{transform:translateY(0)}40%{transform:translateY(-6px)}}
  @keyframes spin{to{transform:rotate(360deg)}}
  *{box-sizing:border-box}
  ::-webkit-scrollbar{width:4px}
  ::-webkit-scrollbar-track{background:#060610}
  ::-webkit-scrollbar-thumb{background:#1e1e3a;border-radius:2px}
  input::placeholder{color:#374151}
`;

const stripAnsi = (s) =>
  typeof s === "string" ? s.replace(/\x1b\[[0-9;]*m/g, "") : JSON.stringify(s, null, 2);

function Dots() {
  return (
    <span style={{ display:"inline-flex", gap:3, alignItems:"center" }}>
      {[0,1,2].map(i => (
        <span key={i} style={{
          width:6, height:6, borderRadius:"50%", background:"#7c3aed",
          display:"inline-block",
          animation:`bounce 1.2s ease-in-out ${i*0.2}s infinite`
        }}/>
      ))}
    </span>
  );
}

function ScanResult({ result }) {
  const [open, setOpen] = useState(false);
  if (!result) return null;
  return (
    <div style={{ background:"#0a0a14", border:"1px solid #1e1e3a", borderRadius:8, marginTop:8, overflow:"hidden" }}>
      <div onClick={() => setOpen(o => !o)}
        style={{ display:"flex", alignItems:"center", gap:10, padding:"8px 14px", cursor:"pointer" }}>
        <span style={{ fontSize:11, color:"#7c3aed", fontWeight:600 }}>SCAN RESULT</span>
        <span style={{ fontSize:11, color:"#4a5568", flex:1 }}>{result.target || result.domain}</span>
        <span style={{ fontSize:11, color:"#374151" }}>{result.duration ? result.duration + "s" : ""}</span>
        <span style={{ fontSize:11, color:"#4a5568" }}>{open ? "▲" : "▼"}</span>
      </div>
      {open && (
        <div style={{ borderTop:"1px solid #1e1e3a", padding:"10px 14px", maxHeight:400, overflowY:"auto" }}>
          <pre style={{ margin:0, fontSize:11, color:"#94a3b8", whiteSpace:"pre-wrap", lineHeight:1.6, fontFamily:"inherit" }}>
            {stripAnsi(result.output || JSON.stringify(result, null, 2))}
          </pre>
        </div>
      )}
    </div>
  );
}

function Msg({ msg }) {
  if (msg.role === "system") return (
    <div style={{ textAlign:"center", margin:"6px 0" }}>
      <span style={{ fontSize:10, color:"#374151", background:"#0f0f1a", padding:"3px 12px", borderRadius:12 }}>
        {msg.content}
      </span>
    </div>
  );

  const user = msg.role === "user";
  const sk   = SKILLS.find(s => s.id === msg.skill);

  return (
    <div style={{ display:"flex", justifyContent:user?"flex-end":"flex-start", marginBottom:14, gap:10, alignItems:"flex-start" }}>
      {!user && (
        <div style={{
          width:30, height:30, borderRadius:7, flexShrink:0, marginTop:2,
          background:"linear-gradient(135deg,#7c3aed,#ec4899)",
          display:"flex", alignItems:"center", justifyContent:"center", fontSize:14
        }}>⬡</div>
      )}
      <div style={{ maxWidth:"80%" }}>
        {!user && (
          <p style={{ fontSize:9, color:"#4a5568", margin:"0 0 3px", fontWeight:600, letterSpacing:1 }}>NEUROSPLOIT</p>
        )}
        <div style={{
          background: user ? "#1a0a2e" : "#0f0f1a",
          border: "1px solid " + (user ? "#7c3aed44" : "#1e1e3a"),
          borderRadius: user ? "14px 4px 14px 14px" : "4px 14px 14px 14px",
          padding:"10px 14px"
        }}>
          {msg.typing
            ? <Dots/>
            : <p style={{ fontSize:13, color:"#e2e8f0", margin:0, lineHeight:1.7, whiteSpace:"pre-wrap" }}>{msg.content}</p>
          }
        </div>
        {msg.result && <ScanResult result={msg.result}/>}
        {sk && (
          <span style={{
            display:"inline-block", marginTop:5, fontSize:10, padding:"2px 8px", borderRadius:4,
            background: sk.color + "22", color: sk.color, border:"1px solid " + sk.color + "44"
          }}>{sk.label}</span>
        )}
      </div>
    </div>
  );
}

export default function NeuroSploit() {
  const [target,   setTarget]   = useState("");
  const [input,    setInput]    = useState("");
  const [messages, setMessages] = useState([{
    role:"assistant",
    content:"NeuroSploit online. Set your target, pick a skill, or type a command.\nAll testing requires prior written authorization."
  }]);
  const [loading,  setLoading]  = useState(false);
  const [tab,      setTab]      = useState("chat");
  const [logs,     setLogs]     = useState([]);
  const [health,   setHealth]   = useState(null);
  const bottomRef = useRef();

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior:"smooth" }); }, [messages]);

  useEffect(() => {
    fetch(API + "/health")
      .then(r => r.json())
      .then(d => setHealth({ ok:true, ...d }))
      .catch(() => setHealth({ ok:false }));
  }, []);

  const allResults = messages.filter(m => m.result);

  const addLog = (entry) =>
    setLogs(p => [{ ...entry, time: new Date().toLocaleTimeString() }, ...p].slice(0, 50));

  const push = (role, content, extra = {}) =>
    setMessages(p => [...p, { role, content, ...extra }]);

  const runSkill = async (skillId, body) => {
    const sk = SKILLS.find(s => s.id === skillId);
    if (!sk || !sk.endpoint) {
      push("assistant", sk ? sk.label + " requires prior scan findings. Run recon and vuln scans first." : "Unknown skill.");
      return;
    }
    if (!body.target && !body.domain) {
      push("assistant", "Set a target first.");
      return;
    }

    setLoading(true);
    setMessages(p => [...p, { role:"assistant", content:"", typing:true }]);
    addLog({ type:"start", skill:skillId, target: body.target || body.domain });

    try {
      const res  = await fetch(API + sk.endpoint, {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();

      setMessages(p => [...p.slice(0, -1), {
        role:"assistant",
        content: data.error
          ? "Error: " + data.error
          : "Scan complete. Duration: " + (data.duration || "?") + "s",
        result: data,
        skill:  skillId,
      }]);
      addLog({ type:"done", skill:skillId, target: body.target || body.domain, duration: data.duration });
    } catch (e) {
      setMessages(p => [...p.slice(0, -1), {
        role:"assistant",
        content:"Backend unreachable. Make sure Flask is running:\n\ncd ~/AI_Pentesting/claude-code-pentest/backend\npython app.py"
      }]);
      addLog({ type:"error", skill:skillId, error: e.message });
    }
    setLoading(false);
  };

  const handleInput = async () => {
    if (!input.trim() || loading) return;
    const txt = input.trim();
    push("user", txt);
    setInput("");

    const low = txt.toLowerCase();
    const t   = target || (txt.match(/(?:on|test|scan|check)\s+([\w.\-]+\.\w+)/i)||[])[1] || "";

    if (!t) { push("assistant", "What target should I test?"); return; }
    if (!target && t) setTarget(t);

    const domain = t.replace(/https?:\/\//, "").split("/")[0];

    if      (low.includes("full") || low.includes("all"))     await runSkill("lhf-toolkit",           { target:t, module:"all" });
    else if (low.includes("header"))                           await runSkill("lhf-toolkit",           { target:t, module:"headers" });
    else if (low.includes("dns"))                              await runSkill("lhf-toolkit",           { target:t, module:"dns" });
    else if (low.includes("cors") || low.includes("method"))   await runSkill("lhf-toolkit",           { target:t, module:"cors" });
    else if (low.includes("info") || low.includes("disclos"))  await runSkill("lhf-toolkit",           { target:t, module:"info" });
    else if (low.includes("recon") || low.includes("subdom"))  await runSkill("recon-dominator",       { domain });
    else if (low.includes("webapp") || low.includes("sqli"))   await runSkill("webapp-exploit-hunter", { target:t });
    else if (low.includes("api")   || low.includes("bola"))    await runSkill("api-breaker",           { target:t });
    else if (low.includes("cloud") || low.includes("s3"))      await runSkill("cloud-pivot-finder",    { domain });
    else push("assistant",
      "I can run these scans on " + t + ":\n\n" +
      "• Security headers\n• DNS recon\n• HTTP methods & CORS\n• Information disclosure\n" +
      "• Recon (subdomains)\n• Webapp (SQLi, XSS, SSRF)\n• API (BOLA, JWT)\n• Cloud (S3, takeover)\n• Full scan\n\n" +
      "What would you like?"
    );
  };

  const backendOk = health?.ok;

  return (
    <div style={{ fontFamily:"'JetBrains Mono','Fira Code',monospace", background:"#060610", height:"100vh", color:"#e2e8f0", display:"flex", flexDirection:"column" }}>
      <style>{css}</style>

      {/* ── Header ── */}
      <div style={{ borderBottom:"1px solid #1e1e3a", padding:"10px 16px", display:"flex", alignItems:"center", gap:12, background:"#0a0a18", flexWrap:"wrap", flexShrink:0 }}>
        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
          <div style={{ width:32, height:32, borderRadius:7, background:"linear-gradient(135deg,#7c3aed,#ec4899)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:15 }}>⬡</div>
          <div>
            <p style={{ margin:0, fontSize:13, fontWeight:700, background:"linear-gradient(90deg,#7c3aed,#ec4899)", WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent" }}>NEUROSPLOIT</p>
            <p style={{ margin:0, fontSize:8, color:"#374151", letterSpacing:2 }}>BY MAEITSEC · OFFENSIVE AI</p>
          </div>
        </div>

        <input
          value={target} onChange={e => setTarget(e.target.value)}
          placeholder="target.com"
          style={{ flex:1, maxWidth:280, background:"#0f0f1a", border:"1px solid #1e1e3a", borderRadius:6, padding:"5px 12px", color:"#e2e8f0", fontSize:12, outline:"none", fontFamily:"inherit" }}
        />

        {/* Backend status pill */}
        <div style={{
          display:"flex", alignItems:"center", gap:5, padding:"4px 10px", borderRadius:6,
          background: backendOk ? "#14b8a622" : health ? "#ef444422" : "#1e1e3a",
          border: "1px solid " + (backendOk ? "#14b8a644" : health ? "#ef444444" : "#1e1e3a")
        }}>
          <span style={{ width:6, height:6, borderRadius:"50%", display:"inline-block", background: backendOk ? "#14b8a6" : health ? "#ef4444" : "#374151" }}/>
          <span style={{ fontSize:10, color: backendOk ? "#14b8a6" : health ? "#ef4444" : "#374151" }}>
            {backendOk ? "BACKEND OK" : health ? "BACKEND DOWN" : "CHECKING..."}
          </span>
        </div>

        <span style={{ fontSize:11, color:"#374151", marginLeft:"auto" }}>{allResults.length} scans</span>
      </div>

      {/* ── Skills bar ── */}
      <div style={{ display:"flex", gap:6, padding:"8px 16px", borderBottom:"1px solid #1e1e3a", background:"#080814", overflowX:"auto", flexShrink:0 }}>
        {SKILLS.map(s => (
          <button key={s.id} title={s.desc}
            onClick={() => {
              if (!target) { push("assistant","Set a target first."); return; }
              const domain = target.replace(/https?:\/\//, "").split("/")[0];
              const body   = (s.endpoint?.includes("recon") || s.endpoint?.includes("cloud"))
                ? { domain }
                : { target };
              if (s.endpoint) runSkill(s.id, body);
              else push("assistant", s.label + " requires prior scan findings. Run recon and vuln scans first, then chain.");
            }}
            style={{
              display:"flex", alignItems:"center", gap:5, padding:"4px 12px", borderRadius:6, cursor:"pointer",
              border:"1px solid " + s.color + "44", background: s.color + "11",
              color: s.color, fontSize:11, fontWeight:500, whiteSpace:"nowrap", fontFamily:"inherit"
            }}
          >⬡ {s.label}</button>
        ))}

        <div style={{ width:1, background:"#1e1e3a", margin:"0 4px", flexShrink:0 }}/>

        <button
          onClick={() => {
            if (!target) { push("assistant","Set a target first."); return; }
            const domain = target.replace(/https?:\/\//, "").split("/")[0];
            const steps  = [
              { id:"lhf-toolkit",           body:{ target, module:"all" } },
              { id:"recon-dominator",        body:{ domain } },
              { id:"webapp-exploit-hunter",  body:{ target } },
              { id:"api-breaker",            body:{ target } },
              { id:"cloud-pivot-finder",     body:{ domain } },
            ];
            steps.forEach((s, i) => setTimeout(() => runSkill(s.id, s.body), i * 3000));
          }}
          style={{ padding:"4px 14px", borderRadius:6, cursor:"pointer", border:"1px solid #7c3aed88", background:"#7c3aed22", color:"#c084fc", fontSize:11, fontWeight:700, whiteSpace:"nowrap", fontFamily:"inherit", letterSpacing:0.5 }}
        >⚡ FULL CHAIN</button>
      </div>

      {/* ── Tabs ── */}
      <div style={{ display:"flex", borderBottom:"1px solid #1e1e3a", background:"#080814", flexShrink:0 }}>
        {["chat","results","logs"].map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding:"7px 18px", fontSize:10, fontWeight:600, cursor:"pointer", background:"transparent",
            border:"none", fontFamily:"inherit", letterSpacing:1, textTransform:"uppercase",
            color: tab===t ? "#7c3aed" : "#374151",
            borderBottom: tab===t ? "2px solid #7c3aed" : "2px solid transparent"
          }}>
            {t}
            {t==="results" && allResults.length > 0 ? " (" + allResults.length + ")" : ""}
            {t==="logs"    && logs.length    > 0 ? " (" + logs.length    + ")" : ""}
          </button>
        ))}
      </div>

      {/* ── Chat tab ── */}
      {tab === "chat" && (
        <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>
          {health && !backendOk && (
            <div style={{ background:"#ef444411", border:"1px solid #ef444433", margin:"12px 16px 0", borderRadius:8, padding:"10px 14px", flexShrink:0 }}>
              <p style={{ margin:0, fontSize:12, color:"#ef4444", fontWeight:600 }}>Backend not running</p>
              <p style={{ margin:"4px 0 0", fontSize:11, color:"#94a3b8" }}>
                In WSL run: <code style={{ color:"#f97316" }}>cd ~/AI_Pentesting/claude-code-pentest/backend && python app.py</code>
              </p>
            </div>
          )}

          <div style={{ flex:1, overflowY:"auto", padding:"14px 16px 8px" }}>
            {messages.map((m, i) => <Msg key={i} msg={m}/>)}
            <div ref={bottomRef}/>
          </div>

          {/* Quick prompts */}
          <div style={{ padding:"0 16px 6px", display:"flex", gap:6, flexWrap:"wrap", flexShrink:0 }}>
            {[
              ["Headers",  () => runSkill("lhf-toolkit", { target, module:"headers" })],
              ["DNS",      () => runSkill("lhf-toolkit", { target, module:"dns" })],
              ["CORS",     () => runSkill("lhf-toolkit", { target, module:"cors" })],
              ["Info Disc",() => runSkill("lhf-toolkit", { target, module:"info" })],
              ["Recon",    () => runSkill("recon-dominator", { domain: target.replace(/https?:\/\//, "").split("/")[0] })],
              ["Full LHF", () => runSkill("lhf-toolkit", { target, module:"all" })],
            ].map(([label, fn]) => (
              <button key={label} onClick={fn}
                style={{ fontSize:10, padding:"3px 10px", borderRadius:4, cursor:"pointer", background:"#0f0f1a", border:"1px solid #1e1e3a", color:"#4a5568", fontFamily:"inherit" }}>
                {label}
              </button>
            ))}
          </div>

          {/* Input bar */}
          <div style={{ padding:"0 16px 14px", display:"flex", gap:8, flexShrink:0 }}>
            <input
              value={input} onChange={e => setInput(e.target.value)} disabled={loading}
              onKeyDown={e => { if (e.key==="Enter" && !e.shiftKey) { e.preventDefault(); handleInput(); } }}
              placeholder={target ? "Test " + target + "..." : "Set target above, then describe what to test..."}
              style={{ flex:1, background:"#0f0f1a", border:"1px solid #1e1e3a", borderRadius:8, padding:"9px 14px", color:"#e2e8f0", fontSize:13, outline:"none", fontFamily:"inherit" }}
            />
            <button onClick={handleInput} disabled={loading || !input.trim()}
              style={{
                padding:"9px 18px", borderRadius:8, border:"none", cursor:"pointer", fontFamily:"inherit", fontSize:13, fontWeight:600,
                background: loading || !input.trim() ? "#1e1e3a" : "linear-gradient(135deg,#7c3aed,#ec4899)",
                color: loading || !input.trim() ? "#374151" : "#fff"
              }}>{loading ? "..." : "→"}</button>
          </div>
        </div>
      )}

      {/* ── Results tab ── */}
      {tab === "results" && (
        <div style={{ flex:1, overflowY:"auto", padding:16 }}>
          {allResults.length === 0
            ? <div style={{ textAlign:"center", padding:60, color:"#374151" }}><p style={{ fontSize:28, margin:"0 0 10px" }}>⬡</p><p style={{ fontSize:13 }}>No scans yet.</p></div>
            : allResults.map((m, i) => {
                const sk = SKILLS.find(s => s.id === m.skill);
                return (
                  <div key={i} style={{ marginBottom:16 }}>
                    <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6 }}>
                      <span style={{ fontSize:10, color: sk?.color || "#7c3aed", fontWeight:600, letterSpacing:1 }}>{m.skill}</span>
                      <span style={{ fontSize:10, color:"#374151" }}>{m.result?.target || m.result?.domain}</span>
                      <span style={{ fontSize:10, color:"#374151", marginLeft:"auto" }}>{m.result?.duration}s</span>
                    </div>
                    <div style={{ background:"#0a0a14", border:"1px solid #1e1e3a", borderRadius:8, padding:"12px 14px", maxHeight:320, overflowY:"auto" }}>
                      <pre style={{ margin:0, fontSize:11, color:"#94a3b8", whiteSpace:"pre-wrap", lineHeight:1.6, fontFamily:"inherit" }}>
                        {stripAnsi(m.result?.output || JSON.stringify(m.result, null, 2))}
                      </pre>
                    </div>
                  </div>
                );
              })
          }
        </div>
      )}

      {/* ── Logs tab ── */}
      {tab === "logs" && (
        <div style={{ flex:1, overflowY:"auto", padding:16 }}>
          {logs.length === 0
            ? <div style={{ textAlign:"center", padding:60, color:"#374151" }}><p style={{ fontSize:13 }}>No activity yet.</p></div>
            : logs.map((l, i) => (
                <div key={i} style={{ display:"flex", gap:10, padding:"5px 0", borderBottom:"1px solid #0f0f1a", alignItems:"center" }}>
                  <span style={{ fontSize:10, color:"#374151", flexShrink:0 }}>{l.time}</span>
                  <span style={{ fontSize:10, fontWeight:600, flexShrink:0, color: l.type==="error" ? "#ef4444" : l.type==="done" ? "#14b8a6" : "#7c3aed" }}>{l.type.toUpperCase()}</span>
                  <span style={{ fontSize:10, color: SKILLS.find(s=>s.id===l.skill)?.color || "#7c3aed", flexShrink:0 }}>{l.skill}</span>
                  <span style={{ fontSize:10, color:"#4a5568" }}>{l.target || l.error}</span>
                  {l.duration && <span style={{ fontSize:10, color:"#374151", marginLeft:"auto" }}>{l.duration}s</span>}
                </div>
              ))
          }
        </div>
      )}
    </div>
  );
}
