import { useState, useRef, useEffect } from "react";

const SKILLS = [
  { id: "recon-dominator",       label: "Recon",       color: "#7c3aed", desc: "Subdomain enum · Port scan · OSINT · Dorking" },
  { id: "lhf-toolkit",           label: "LHF",         color: "#0ea5e9", desc: "Headers · DNS · CORS · Info Disclosure" },
  { id: "webapp-exploit-hunter", label: "WebApp",      color: "#f97316", desc: "SQLi · XSS · SSRF · IDOR · SSTI · Auth Bypass" },
  { id: "api-breaker",           label: "API",         color: "#ec4899", desc: "BOLA · JWT · GraphQL · Mass Assignment" },
  { id: "cloud-pivot-finder",    label: "Cloud",       color: "#14b8a6", desc: "S3 · Takeover · CI/CD · Serverless" },
  { id: "attack-path-architect", label: "Attack Path", color: "#f59e0b", desc: "MITRE ATT&CK · Kill Chains · Trust Maps" },
  { id: "vuln-chain-composer",   label: "Chain",       color: "#ef4444", desc: "Exploit Chains · CVSS · Bug Bounty Reports" },
];

const SEV_COLOR = { CRITICAL:"#ef4444", HIGH:"#f97316", MEDIUM:"#f59e0b", LOW:"#3b82f6", INFO:"#6b7280" };

const QUICK_PROMPTS = [
  { label:"Full Pentest",   prompt:"I have authorization. Run a full penetration test pipeline on {target}. Use all skills in sequence and chain the findings." },
  { label:"Recon Only",     prompt:"Run full reconnaissance on {target} using recon-dominator." },
  { label:"LHF Checks",     prompt:"Run all low hanging fruit checks on {target}: headers, DNS, CORS, info disclosure." },
  { label:"API Test",       prompt:"Test all APIs on {target} using api-breaker. Focus on BOLA, JWT, and mass assignment." },
  { label:"Chain Findings", prompt:"Take all findings so far and use vuln-chain-composer to build exploit chains and generate a bug bounty report." },
];

const css = `
  @keyframes bounce { 0%,80%,100%{transform:translateY(0)} 40%{transform:translateY(-6px)} }
  @keyframes pulse  { 0%,100%{opacity:1} 50%{opacity:0.4} }
  * { box-sizing: border-box; }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: #060610; }
  ::-webkit-scrollbar-thumb { background: #1e1e3a; border-radius: 2px; }
`;

function TypingDots() {
  return (
    <span style={{display:"inline-flex",gap:3,alignItems:"center"}}>
      {[0,1,2].map(i=>(
        <span key={i} style={{
          width:6,height:6,borderRadius:"50%",background:"#7c3aed",display:"inline-block",
          animation:`bounce 1.2s ease-in-out ${i*0.2}s infinite`
        }}/>
      ))}
    </span>
  );
}

function SeverityBadge({ sev }) {
  const c = SEV_COLOR[sev] || "#6b7280";
  return (
    <span style={{
      fontSize:10,fontWeight:600,padding:"2px 7px",borderRadius:4,letterSpacing:0.5,
      background:c+"22",color:c,border:"1px solid "+c+"44"
    }}>{sev}</span>
  );
}

function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{background:"#0f0f1a",border:"1px solid #1e1e3a",borderRadius:8,marginBottom:8,overflow:"hidden"}}>
      <div onClick={()=>setOpen(o=>!o)} style={{display:"flex",alignItems:"center",gap:10,padding:"10px 14px",cursor:"pointer"}}>
        <SeverityBadge sev={finding.severity}/>
        <span style={{flex:1,fontSize:13,color:"#e2e8f0"}}>{finding.title}</span>
        <span style={{fontSize:11,color:"#4a5568",marginRight:8}}>{finding.target}</span>
        <span style={{color:"#4a5568",fontSize:11}}>{open?"▲":"▼"}</span>
      </div>
      {open && (
        <div style={{padding:"0 14px 14px",borderTop:"1px solid #1e1e3a"}}>
          <p style={{fontSize:12,color:"#94a3b8",margin:"10px 0 6px",lineHeight:1.6}}>{finding.description}</p>
          {finding.cvss && (
            <p style={{fontSize:11,color:"#7c3aed",margin:"4px 0"}}>CVSS: {finding.cvss} {finding.cwe ? "· "+finding.cwe : ""}</p>
          )}
          {finding.recommendation && (
            <div style={{background:"#0a0a14",borderRadius:6,padding:"8px 10px",marginTop:8}}>
              <p style={{fontSize:11,color:"#4ade80",margin:0}}>Fix: {finding.recommendation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function MsgBubble({ msg }) {
  if (msg.role === "system") {
    return (
      <div style={{textAlign:"center",margin:"8px 0"}}>
        <span style={{fontSize:11,color:"#374151",background:"#0f0f1a",padding:"3px 12px",borderRadius:12}}>{msg.content}</span>
      </div>
    );
  }
  const isUser = msg.role === "user";
  return (
    <div style={{display:"flex",justifyContent:isUser?"flex-end":"flex-start",marginBottom:16,gap:10,alignItems:"flex-start"}}>
      {!isUser && (
        <div style={{
          width:32,height:32,borderRadius:8,flexShrink:0,marginTop:2,
          background:"linear-gradient(135deg,#7c3aed,#ec4899)",
          display:"flex",alignItems:"center",justifyContent:"center",fontSize:16
        }}>⬡</div>
      )}
      <div style={{maxWidth:"78%"}}>
        {!isUser && <p style={{fontSize:10,color:"#4a5568",margin:"0 0 4px",fontWeight:600,letterSpacing:1}}>NEUROSPLOIT</p>}
        <div style={{
          background: isUser ? "#1a0a2e" : "#0f0f1a",
          border: "1px solid " + (isUser ? "#7c3aed44" : "#1e1e3a"),
          borderRadius: isUser ? "16px 4px 16px 16px" : "4px 16px 16px 16px",
          padding:"12px 16px"
        }}>
          {msg.typing
            ? <TypingDots/>
            : <p style={{fontSize:13,color:"#e2e8f0",margin:0,lineHeight:1.7,whiteSpace:"pre-wrap"}}>{msg.content}</p>
          }
        </div>
        {msg.findings && msg.findings.length > 0 && (
          <div style={{marginTop:10}}>
            <p style={{fontSize:11,color:"#4a5568",margin:"0 0 6px",fontWeight:600,letterSpacing:1}}>
              {msg.findings.length} FINDING{msg.findings.length>1?"S":""} DETECTED
            </p>
            {msg.findings.map((f,i)=><FindingCard key={i} finding={f}/>)}
          </div>
        )}
        {msg.skillUsed && msg.skillUsed.length > 0 && (
          <div style={{marginTop:6,display:"flex",gap:6,flexWrap:"wrap"}}>
            {msg.skillUsed.map(s=>{
              const sk = SKILLS.find(x=>x.id===s);
              return sk ? (
                <span key={s} style={{
                  fontSize:10,padding:"2px 8px",borderRadius:4,
                  background:sk.color+"22",color:sk.color,border:"1px solid "+sk.color+"44"
                }}>{sk.label}</span>
              ) : null;
            })}
          </div>
        )}
      </div>
    </div>
  );
}

export default function NeuroSploit() {
  const [target, setTarget]       = useState("");
  const [input, setInput]         = useState("");
  const [messages, setMessages]   = useState([{
    role:"assistant",
    content:"NeuroSploit online. Set a target and select a skill — or describe what you want to test. All operations require prior written authorization."
  }]);
  const [loading, setLoading]     = useState(false);
  const [activeSkills, setActiveSkills] = useState([]);
  const [tab, setTab]             = useState("chat");
  const [allFindings, setAllFindings]   = useState([]);
  const [history, setHistory]     = useState([]);
  const bottomRef = useRef();
  const inputRef  = useRef();

  useEffect(()=>{ bottomRef.current?.scrollIntoView({behavior:"smooth"}); }, [messages]);

  const buildSystem = () =>
    "You are NeuroSploit, an elite AI-powered penetration testing assistant built by maeitsec.\n\n" +
    "Skills available:\n" +
    SKILLS.map(s=>"- "+s.id+": "+s.desc).join("\n") + "\n\n" +
    "Current target: " + (target||"not set") + "\n\n" +
    "Rules:\n" +
    "1. Be direct and technical — no fluff\n" +
    "2. Simulate running the relevant skill(s) and return realistic findings\n" +
    "3. If there are findings, append them at the end in this exact format (no newlines inside):\n" +
    'FINDINGS_JSON:[{"title":"...","severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","target":"...","description":"...","cvss":"...","cwe":"...","recommendation":"..."}]\n' +
    "4. Note which skills you are using\n" +
    "5. Always require authorization confirmation\n" +
    "6. For chaining, reference previous findings and escalate impact";

  const extractFindings = (text) => {
    const m = text.match(/FINDINGS_JSON:(\[[\s\S]*?\])/);
    if (!m) return { clean:text, findings:[] };
    try {
      return { clean:text.replace(/FINDINGS_JSON:[\s\S]*$/, "").trim(), findings:JSON.parse(m[1]) };
    } catch { return { clean:text, findings:[] }; }
  };

  const detectSkills = (text) =>
    SKILLS.filter(s=>text.toLowerCase().includes(s.id)||text.toLowerCase().includes(s.label.toLowerCase())).map(s=>s.id);

  const send = async (prompt) => {
    if (!prompt.trim() || loading) return;
    const final = prompt.replace("{target}", target||"the target");
    setMessages(p=>[...p, {role:"user",content:final}, {role:"assistant",content:"",typing:true}]);
    setHistory(p=>[...p, {role:"user",content:final}]);
    setInput("");
    setLoading(true);
    try {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          model:"claude-sonnet-4-20250514",
          max_tokens:1000,
          system:buildSystem(),
          messages:[...history, {role:"user",content:final}]
        })
      });
      const data = await res.json();
      const raw = data.content?.[0]?.text || "No response.";
      const {clean, findings} = extractFindings(raw);
      const skillUsed = detectSkills(final+" "+raw);
      setMessages(p=>[...p.slice(0,-1), {role:"assistant",content:clean,findings,skillUsed}]);
      setHistory(p=>[...p, {role:"assistant",content:raw}]);
      if (findings.length) setAllFindings(p=>[...p,...findings]);
    } catch(e) {
      setMessages(p=>[...p.slice(0,-1), {role:"assistant",content:"Error: "+e.message}]);
    }
    setLoading(false);
  };

  const critCount = allFindings.filter(f=>f.severity==="CRITICAL").length;
  const highCount = allFindings.filter(f=>f.severity==="HIGH").length;

  return (
    <div style={{fontFamily:"'JetBrains Mono','Fira Code',monospace",background:"#060610",minHeight:"600px",color:"#e2e8f0",display:"flex",flexDirection:"column"}}>
      <style>{css}</style>

      {/* ── Header ── */}
      <div style={{borderBottom:"1px solid #1e1e3a",padding:"10px 16px",display:"flex",alignItems:"center",gap:12,background:"#0a0a18",flexWrap:"wrap"}}>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          <div style={{width:34,height:34,borderRadius:8,background:"linear-gradient(135deg,#7c3aed,#ec4899)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:16}}>⬡</div>
          <div>
            <p style={{margin:0,fontSize:14,fontWeight:700,background:"linear-gradient(90deg,#7c3aed,#ec4899)",WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent"}}>NEUROSPLOIT</p>
            <p style={{margin:0,fontSize:8,color:"#374151",letterSpacing:2}}>BY MAEITSEC · OFFENSIVE AI</p>
          </div>
        </div>
        <input
          value={target} onChange={e=>setTarget(e.target.value)}
          placeholder="target.com"
          style={{flex:1,maxWidth:300,background:"#0f0f1a",border:"1px solid #1e1e3a",borderRadius:6,padding:"6px 12px",color:"#e2e8f0",fontSize:12,outline:"none",fontFamily:"inherit"}}
        />
        {target && (
          <span style={{fontSize:11,color:"#7c3aed",background:"#7c3aed22",border:"1px solid #7c3aed44",padding:"3px 10px",borderRadius:6}}>
            ● {target}
          </span>
        )}
        <div style={{marginLeft:"auto",display:"flex",gap:10}}>
          {critCount>0 && <span style={{fontSize:11,color:"#ef4444",fontWeight:600}}>{critCount} CRIT</span>}
          {highCount>0 && <span style={{fontSize:11,color:"#f97316",fontWeight:600}}>{highCount} HIGH</span>}
          <span style={{fontSize:11,color:"#374151"}}>{allFindings.length} TOTAL</span>
        </div>
      </div>

      {/* ── Skills bar ── */}
      <div style={{display:"flex",gap:6,padding:"8px 16px",borderBottom:"1px solid #1e1e3a",background:"#080814",overflowX:"auto",flexShrink:0}}>
        {SKILLS.map(s=>(
          <button key={s.id}
            title={s.desc}
            onClick={()=>{ if(target) send("Use "+s.id+" on "+target); }}
            style={{
              display:"flex",alignItems:"center",gap:5,padding:"4px 12px",borderRadius:6,cursor:"pointer",
              border:"1px solid "+s.color+"44",background:activeSkills.includes(s.id)?s.color+"33":s.color+"11",
              color:s.color,fontSize:11,fontWeight:500,whiteSpace:"nowrap",fontFamily:"inherit"
            }}
          >⬡ {s.label}</button>
        ))}
        <div style={{width:1,background:"#1e1e3a",margin:"0 4px",flexShrink:0}}/>
        <button
          onClick={()=>{
            if(!target){alert("Set a target first");return;}
            send("I have authorization to test "+target+". Run a full penetration test using all skills in sequence: recon-dominator, lhf-toolkit, webapp-exploit-hunter, api-breaker, cloud-pivot-finder, attack-path-architect, vuln-chain-composer. Chain all findings.");
          }}
          style={{padding:"4px 14px",borderRadius:6,cursor:"pointer",border:"1px solid #7c3aed88",background:"#7c3aed22",color:"#c084fc",fontSize:11,fontWeight:700,whiteSpace:"nowrap",fontFamily:"inherit",letterSpacing:0.5}}
        >⚡ FULL CHAIN</button>
      </div>

      {/* ── Tabs ── */}
      <div style={{display:"flex",borderBottom:"1px solid #1e1e3a",background:"#080814",flexShrink:0}}>
        {["chat","findings","report"].map(t=>(
          <button key={t} onClick={()=>setTab(t)} style={{
            padding:"7px 18px",fontSize:10,fontWeight:600,cursor:"pointer",background:"transparent",
            border:"none",fontFamily:"inherit",letterSpacing:1,textTransform:"uppercase",
            color:tab===t?"#7c3aed":"#374151",
            borderBottom:tab===t?"2px solid #7c3aed":"2px solid transparent"
          }}>{t}{t==="findings"&&allFindings.length>0?" ("+allFindings.length+")":""}</button>
        ))}
      </div>

      {/* ── Chat tab ── */}
      {tab==="chat" && (
        <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
          <div style={{flex:1,overflowY:"auto",padding:"16px 16px 8px"}}>
            {messages.map((m,i)=><MsgBubble key={i} msg={m}/>)}
            <div ref={bottomRef}/>
          </div>
          <div style={{padding:"0 16px 6px",display:"flex",gap:6,flexWrap:"wrap",flexShrink:0}}>
            {QUICK_PROMPTS.map(q=>(
              <button key={q.label} onClick={()=>send(q.prompt)} style={{
                fontSize:10,padding:"3px 10px",borderRadius:4,cursor:"pointer",
                background:"#0f0f1a",border:"1px solid #1e1e3a",color:"#4a5568",fontFamily:"inherit"
              }}>{q.label}</button>
            ))}
          </div>
          <div style={{padding:"0 16px 14px",display:"flex",gap:8,flexShrink:0}}>
            <input
              ref={inputRef} value={input} onChange={e=>setInput(e.target.value)} disabled={loading}
              onKeyDown={e=>{ if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();send(input);} }}
              placeholder={target?"Test "+target+"...":"Set a target above, then describe what to test..."}
              style={{flex:1,background:"#0f0f1a",border:"1px solid #1e1e3a",borderRadius:8,padding:"10px 14px",color:"#e2e8f0",fontSize:13,outline:"none",fontFamily:"inherit"}}
            />
            <button onClick={()=>send(input)} disabled={loading||!input.trim()} style={{
              padding:"10px 18px",borderRadius:8,border:"none",cursor:"pointer",fontFamily:"inherit",fontSize:13,fontWeight:600,
              background:loading||!input.trim()?"#1e1e3a":"linear-gradient(135deg,#7c3aed,#ec4899)",
              color:loading||!input.trim()?"#374151":"#fff"
            }}>{loading?"...":"→"}</button>
          </div>
        </div>
      )}

      {/* ── Findings tab ── */}
      {tab==="findings" && (
        <div style={{flex:1,overflowY:"auto",padding:16}}>
          {allFindings.length===0
            ? <div style={{textAlign:"center",padding:60,color:"#374151"}}><p style={{fontSize:28,margin:"0 0 10px"}}>⬡</p><p style={{fontSize:13}}>No findings yet. Run a scan first.</p></div>
            : <>
                <div style={{display:"flex",gap:10,marginBottom:16,flexWrap:"wrap"}}>
                  {Object.entries(SEV_COLOR).map(([sev,col])=>{
                    const n=allFindings.filter(f=>f.severity===sev).length;
                    if(!n) return null;
                    return (
                      <div key={sev} style={{padding:"8px 14px",borderRadius:8,background:col+"11",border:"1px solid "+col+"33",textAlign:"center"}}>
                        <p style={{margin:0,fontSize:18,fontWeight:700,color:col}}>{n}</p>
                        <p style={{margin:0,fontSize:9,color:col,letterSpacing:1}}>{sev}</p>
                      </div>
                    );
                  })}
                </div>
                {["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(sev=>{
                  const f=allFindings.filter(x=>x.severity===sev);
                  if(!f.length) return null;
                  return (
                    <div key={sev} style={{marginBottom:18}}>
                      <p style={{fontSize:10,color:SEV_COLOR[sev],letterSpacing:2,margin:"0 0 8px",fontWeight:700}}>{sev}</p>
                      {f.map((finding,i)=><FindingCard key={i} finding={finding}/>)}
                    </div>
                  );
                })}
              </>
          }
        </div>
      )}

      {/* ── Report tab ── */}
      {tab==="report" && (
        <div style={{flex:1,overflowY:"auto",padding:16}}>
          {allFindings.length===0
            ? <div style={{textAlign:"center",padding:60,color:"#374151"}}><p style={{fontSize:28,margin:"0 0 10px"}}>⬡</p><p style={{fontSize:13}}>No findings to report yet.</p></div>
            : <div style={{background:"#0a0a18",border:"1px solid #1e1e3a",borderRadius:12,padding:24,maxWidth:780,margin:"0 auto"}}>
                <div style={{borderBottom:"1px solid #1e1e3a",paddingBottom:14,marginBottom:18}}>
                  <p style={{margin:"0 0 4px",fontSize:17,fontWeight:700,background:"linear-gradient(90deg,#7c3aed,#ec4899)",WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent"}}>NEUROSPLOIT SECURITY ASSESSMENT</p>
                  <p style={{margin:0,fontSize:11,color:"#4a5568"}}>Target: {target||"N/A"} · {new Date().toISOString().split("T")[0]} · @maeitsec</p>
                </div>
                <div style={{display:"flex",gap:10,marginBottom:18,flexWrap:"wrap"}}>
                  {Object.entries(SEV_COLOR).map(([sev,col])=>{
                    const n=allFindings.filter(f=>f.severity===sev).length;
                    if(!n) return null;
                    return (
                      <div key={sev} style={{padding:"6px 12px",borderRadius:6,background:col+"11",border:"1px solid "+col+"33"}}>
                        <p style={{margin:0,fontSize:16,fontWeight:700,color:col}}>{n}</p>
                        <p style={{margin:0,fontSize:9,color:col,letterSpacing:1}}>{sev}</p>
                      </div>
                    );
                  })}
                </div>
                {["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map((sev,si)=>{
                  const f=allFindings.filter(x=>x.severity===sev);
                  if(!f.length) return null;
                  return (
                    <div key={sev} style={{marginBottom:22}}>
                      <p style={{fontSize:11,color:SEV_COLOR[sev],letterSpacing:2,margin:"0 0 10px",fontWeight:700,borderBottom:"1px solid "+SEV_COLOR[sev]+"22",paddingBottom:6}}>
                        {si+1}. {sev} SEVERITY FINDINGS
                      </p>
                      {f.map((finding,i)=>(
                        <div key={i} style={{marginBottom:14,paddingLeft:14,borderLeft:"2px solid "+SEV_COLOR[sev]+"44"}}>
                          <p style={{margin:"0 0 3px",fontSize:13,fontWeight:600,color:"#e2e8f0"}}>{finding.title}</p>
                          <p style={{margin:"0 0 3px",fontSize:11,color:"#64748b"}}>
                            {finding.target}{finding.cvss?" · CVSS: "+finding.cvss:""}{finding.cwe?" · "+finding.cwe:""}
                          </p>
                          <p style={{margin:"0 0 5px",fontSize:12,color:"#94a3b8",lineHeight:1.5}}>{finding.description}</p>
                          {finding.recommendation && <p style={{margin:0,fontSize:11,color:"#4ade80"}}>↳ {finding.recommendation}</p>}
                        </div>
                      ))}
                    </div>
                  );
                })}
                <div style={{borderTop:"1px solid #1e1e3a",paddingTop:14,marginTop:8,textAlign:"center"}}>
                  <p style={{margin:0,fontSize:10,color:"#1e1e3a"}}>Generated by NeuroSploit · @maeitsec · Authorized security testing only</p>
                </div>
              </div>
          }
        </div>
      )}
    </div>
  );
}
