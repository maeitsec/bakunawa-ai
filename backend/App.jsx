import { useState, useRef, useEffect } from "react";

const API = "http://localhost:5000";

const SKILLS = [
  { id:"lhf-toolkit",           label:"LHF",         color:"#0ea5e9", bg:"#0ea5e911", border:"#0ea5e933", endpoint:"/scan/lhf",    desc:"Headers · DNS · CORS · Info Disclosure" },
  { id:"recon-dominator",       label:"Recon",        color:"#a78bfa", bg:"#a78bfa11", border:"#a78bfa33", endpoint:"/scan/recon",  desc:"Subdomain enum · Port scan · OSINT" },
  { id:"webapp-exploit-hunter", label:"WebApp",       color:"#fb923c", bg:"#fb923c11", border:"#fb923c33", endpoint:"/scan/webapp", desc:"SQLi · XSS · SSRF · IDOR · SSTI" },
  { id:"api-breaker",           label:"API",          color:"#f472b6", bg:"#f472b611", border:"#f472b633", endpoint:"/scan/api",    desc:"BOLA · JWT · GraphQL · Mass Assignment" },
  { id:"cloud-pivot-finder",    label:"Cloud",        color:"#2dd4bf", bg:"#2dd4bf11", border:"#2dd4bf33", endpoint:"/scan/cloud",  desc:"S3 · Takeover · CI/CD · Serverless" },
  { id:"attack-path-architect", label:"Paths",        color:"#fbbf24", bg:"#fbbf2411", border:"#fbbf2433", endpoint:null,           desc:"MITRE ATT&CK · Kill Chains" },
  { id:"vuln-chain-composer",   label:"Chain",        color:"#f87171", bg:"#f8717111", border:"#f8717133", endpoint:null,           desc:"Exploit Chains · Bug Bounty Reports" },
];

const SEV = {
  CRITICAL: { color:"#ef4444", bg:"#ef444415", label:"CRIT" },
  HIGH:     { color:"#f97316", bg:"#f9731615", label:"HIGH" },
  MEDIUM:   { color:"#f59e0b", bg:"#f59e0b15", label:"MED"  },
  LOW:      { color:"#3b82f6", bg:"#3b82f615", label:"LOW"  },
  INFO:     { color:"#6b7280", bg:"#6b728015", label:"INFO" },
};

const QUICK = [
  { label:"All checks",  mod:"all"     },
  { label:"Headers",     mod:"headers" },
  { label:"DNS",         mod:"dns"     },
  { label:"CORS",        mod:"cors"    },
  { label:"Info Disc",   mod:"info"    },
];

const stripAnsi = s => typeof s==="string" ? s.replace(/\x1b\[[0-9;]*m/g,"") : JSON.stringify(s,null,2);

const css = `
  @keyframes pulse-dot { 0%,100%{opacity:1} 50%{opacity:.3} }
  @keyframes bounce { 0%,80%,100%{transform:translateY(0)} 40%{transform:translateY(-5px)} }
  @keyframes fadein { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
  @keyframes scanline { 0%{top:-40px} 100%{top:100%} }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#030308}
  ::-webkit-scrollbar{width:3px;height:3px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:#ffffff18;border-radius:2px}
  input,button{font-family:inherit}
  input::placeholder{color:#ffffff25}
  .msg-in{animation:fadein .2s ease}
  .sk-btn:hover{filter:brightness(1.3);transform:translateY(-1px)}
  .sk-btn{transition:all .15s}
  .quick-btn:hover{background:#ffffff0a!important;color:#ffffffcc!important}
  .tab-btn:hover{color:#ffffffaa!important}
  .send-btn:hover:not(:disabled){filter:brightness(1.15);transform:scale(1.02)}
  .result-card:hover{border-color:#ffffff22!important}
`;

function StatusDot({ ok }) {
  return (
    <span style={{display:"inline-flex",alignItems:"center",gap:5}}>
      <span style={{
        width:7,height:7,borderRadius:"50%",display:"inline-block",
        background: ok===null?"#ffffff30": ok?"#22c55e":"#ef4444",
        animation: ok===null?"pulse-dot 1.5s infinite":ok?"pulse-dot 2s infinite":"none",
        boxShadow: ok?"0 0 6px #22c55e88":ok===false?"0 0 6px #ef444488":"none"
      }}/>
      <span style={{fontSize:10,fontWeight:600,letterSpacing:.8,
        color: ok===null?"#ffffff40": ok?"#22c55e":"#ef4444"
      }}>
        {ok===null?"CHECKING": ok?"ONLINE":"OFFLINE"}
      </span>
    </span>
  );
}

function Dots() {
  return (
    <span style={{display:"inline-flex",gap:4,alignItems:"center",padding:"2px 0"}}>
      {[0,1,2].map(i=>(
        <span key={i} style={{
          width:5,height:5,borderRadius:"50%",background:"#a78bfa",display:"inline-block",
          animation:`bounce 1s ease-in-out ${i*.18}s infinite`
        }}/>
      ))}
    </span>
  );
}

function SevBadge({ sev }) {
  const s = SEV[sev]||SEV.INFO;
  return (
    <span style={{
      fontSize:9,fontWeight:700,padding:"2px 6px",borderRadius:3,letterSpacing:.8,
      background:s.bg, color:s.color, border:"1px solid "+s.color+"44", flexShrink:0
    }}>{s.label}</span>
  );
}

function ResultPanel({ result }) {
  const [open, setOpen] = useState(false);
  if (!result) return null;
  const sk = SKILLS.find(s=>s.id===result.skill);
  return (
    <div className="result-card" onClick={()=>setOpen(o=>!o)} style={{
      background:"#0a0a1a",border:"1px solid #ffffff0f",borderRadius:8,
      marginTop:10,overflow:"hidden",cursor:"pointer",transition:"border-color .15s"
    }}>
      <div style={{display:"flex",alignItems:"center",gap:8,padding:"9px 14px"}}>
        <div style={{width:6,height:6,borderRadius:"50%",background:sk?.color||"#a78bfa",flexShrink:0}}/>
        <span style={{fontSize:11,fontWeight:600,color:sk?.color||"#a78bfa",letterSpacing:.5}}>{result.skill}</span>
        <span style={{fontSize:11,color:"#ffffff40",flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{result.target||result.domain}</span>
        {result.duration && <span style={{fontSize:10,color:"#ffffff25",flexShrink:0}}>{result.duration}s</span>}
        <span style={{fontSize:10,color:"#ffffff25",flexShrink:0,marginLeft:4}}>{open?"▲":"▼"}</span>
      </div>
      {open && (
        <div style={{borderTop:"1px solid #ffffff08",padding:"10px 14px",maxHeight:360,overflowY:"auto"}}>
          <pre style={{fontSize:11,color:"#94a3b8",whiteSpace:"pre-wrap",lineHeight:1.65,fontFamily:"'JetBrains Mono',monospace"}}>
            {stripAnsi(result.output||JSON.stringify(result,null,2))}
          </pre>
        </div>
      )}
    </div>
  );
}

function Bubble({ msg }) {
  const isUser = msg.role==="user";
  const sk = SKILLS.find(s=>s.id===msg.skill);

  if (msg.role==="sys") return (
    <div style={{textAlign:"center",margin:"4px 0"}}>
      <span style={{fontSize:10,color:"#ffffff20",background:"#ffffff08",padding:"2px 12px",borderRadius:10,letterSpacing:.5}}>
        {msg.content}
      </span>
    </div>
  );

  return (
    <div className="msg-in" style={{
      display:"flex",justifyContent:isUser?"flex-end":"flex-start",
      marginBottom:12,gap:9,alignItems:"flex-start"
    }}>
      {!isUser && (
        <div style={{
          width:28,height:28,borderRadius:7,flexShrink:0,marginTop:1,
          background:"linear-gradient(135deg,#7c3aed,#db2777)",
          display:"flex",alignItems:"center",justifyContent:"center",fontSize:12
        }}>N</div>
      )}
      <div style={{maxWidth:"82%",minWidth:0}}>
        {!isUser && (
          <p style={{fontSize:9,color:"#ffffff30",margin:"0 0 4px",fontWeight:700,letterSpacing:1.5}}>NEUROSPLOIT</p>
        )}
        <div style={{
          background: isUser ? "#1e1040" : "#0d0d20",
          border:"1px solid "+(isUser?"#7c3aed30":"#ffffff0a"),
          borderRadius: isUser?"12px 3px 12px 12px":"3px 12px 12px 12px",
          padding:"10px 14px"
        }}>
          {msg.typing ? <Dots/> : (
            <p style={{fontSize:13,color:"#e2e8f0",lineHeight:1.75,whiteSpace:"pre-wrap"}}>{msg.content}</p>
          )}
        </div>
        {msg.result && <ResultPanel result={msg.result}/>}
        {sk && (
          <span style={{
            display:"inline-block",marginTop:5,fontSize:9,padding:"2px 8px",borderRadius:3,fontWeight:600,letterSpacing:.8,
            background:sk.bg, color:sk.color, border:"1px solid "+sk.border
          }}>{sk.id}</span>
        )}
      </div>
    </div>
  );
}

export default function App() {
  const [target,   setTarget]   = useState("");
  const [input,    setInput]    = useState("");
  const [messages, setMessages] = useState([{
    role:"assistant",
    content:"NeuroSploit initialized.\nSet a target and select a module — or describe what you want to assess.\n\nAll operations require prior written authorization from the target owner."
  }]);
  const [loading,  setLoading]  = useState(false);
  const [tab,      setTab]      = useState("chat");
  const [logs,     setLogs]     = useState([]);
  const [health,   setHealth]   = useState(null);
  const bottomRef = useRef();
  const inputRef  = useRef();

  useEffect(()=>{ bottomRef.current?.scrollIntoView({behavior:"smooth"}); },[messages]);

  useEffect(()=>{
    fetch(API+"/health")
      .then(r=>r.json())
      .then(d=>setHealth({ok:true,...d}))
      .catch(()=>setHealth({ok:false}));
  },[]);

  const allResults = messages.filter(m=>m.result);
  const backendOk  = health?.ok || null;
  const finHealth  = health ? (health.ok ? true : false) : null;

  const addLog = e => setLogs(p=>[{...e,time:new Date().toLocaleTimeString()},...p].slice(0,100));
  const push   = (role,content,extra={}) => setMessages(p=>[...p,{role,content,...extra}]);

  const runSkill = async (skillId, body) => {
    const sk = SKILLS.find(s=>s.id===skillId);
    if (!sk?.endpoint) {
      push("assistant", sk?.label+" requires prior scan findings. Run recon and vuln scans first.");
      return;
    }
    if (!body.target && !body.domain) { push("assistant","Set a target first."); return; }

    setLoading(true);
    setMessages(p=>[...p,{role:"assistant",content:"",typing:true}]);
    addLog({type:"start",skill:skillId,target:body.target||body.domain});

    try {
      const res  = await fetch(API+sk.endpoint, {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify(body),
        signal:AbortSignal.timeout(180000)
      });
      const data = await res.json();
      setMessages(p=>[...p.slice(0,-1),{
        role:"assistant",
        content: data.error ? "Error: "+data.error : "Scan complete — "+( data.duration||"?")+"s elapsed.",
        result:data, skill:skillId
      }]);
      addLog({type:"done",skill:skillId,target:body.target||body.domain,duration:data.duration});
    } catch(e) {
      setMessages(p=>[...p.slice(0,-1),{role:"assistant",content:"Connection failed.\n\nMake sure Flask is running:\ncd ~/AI_Pentesting/claude-code-pentest/backend\npython app.py"}]);
      addLog({type:"error",skill:skillId,error:e.message});
    }
    setLoading(false);
  };

  const handleInput = async () => {
    if (!input.trim()||loading) return;
    const txt   = input.trim();
    push("user",txt);
    setInput("");
    const low   = txt.toLowerCase();
    const t     = target||(txt.match(/(?:on|test|scan|check)\s+([\w.\-]+\.\w+)/i)||[])[1]||"";
    if (!t) { push("assistant","What target should I assess?"); return; }
    if (!target&&t) setTarget(t);
    const domain = t.replace(/https?:\/\//,"").split("/")[0];

    if      (low.includes("full")||low.includes("all"))    runSkill("lhf-toolkit",{target:t,module:"all"});
    else if (low.includes("header"))                        runSkill("lhf-toolkit",{target:t,module:"headers"});
    else if (low.includes("dns"))                           runSkill("lhf-toolkit",{target:t,module:"dns"});
    else if (low.includes("cors")||low.includes("method"))  runSkill("lhf-toolkit",{target:t,module:"cors"});
    else if (low.includes("info")||low.includes("disclos")) runSkill("lhf-toolkit",{target:t,module:"info"});
    else if (low.includes("recon")||low.includes("subdom")) runSkill("recon-dominator",{domain});
    else if (low.includes("webapp")||low.includes("sqli"))  runSkill("webapp-exploit-hunter",{target:t});
    else if (low.includes("api")||low.includes("bola"))     runSkill("api-breaker",{target:t});
    else if (low.includes("cloud")||low.includes("s3"))     runSkill("cloud-pivot-finder",{domain});
    else push("assistant","Available modules for "+t+":\n\n→ Security headers\n→ DNS reconnaissance\n→ HTTP methods & CORS\n→ Information disclosure\n→ Recon (subdomains, OSINT)\n→ Webapp (SQLi, XSS, SSRF, IDOR)\n→ API (BOLA, JWT, GraphQL)\n→ Cloud (S3, takeover, CI/CD)\n→ Full scan (all modules)\n\nWhat would you like to run?");
  };

  const triggerFullChain = () => {
    if (!target) { push("assistant","Set a target first."); return; }
    const domain = target.replace(/https?:\/\//,"").split("/")[0];
    [
      {id:"lhf-toolkit",           body:{target,module:"all"}},
      {id:"recon-dominator",        body:{domain}},
      {id:"webapp-exploit-hunter",  body:{target}},
      {id:"api-breaker",            body:{target}},
      {id:"cloud-pivot-finder",     body:{domain}},
    ].forEach((s,i)=>setTimeout(()=>runSkill(s.id,s.body),i*3500));
  };

  const TABS = ["chat","results","logs"];

  return (
    <div style={{
      fontFamily:"'JetBrains Mono','Fira Code','Consolas',monospace",
      background:"#030308",height:"100vh",color:"#e2e8f0",
      display:"flex",flexDirection:"column",overflow:"hidden"
    }}>
      <style>{css}</style>

      {/* ── Header ── */}
      <div style={{
        background:"#07071a",
        borderBottom:"1px solid #ffffff0a",
        padding:"0 20px",
        display:"flex",alignItems:"center",gap:14,height:52,flexShrink:0
      }}>
        {/* Logo */}
        <div style={{display:"flex",alignItems:"center",gap:10,flexShrink:0}}>
          <div style={{
            width:30,height:30,borderRadius:7,
            background:"linear-gradient(135deg,#7c3aed,#db2777)",
            display:"flex",alignItems:"center",justifyContent:"center",
            fontSize:14,fontWeight:700,color:"#fff",letterSpacing:-1
          }}>N</div>
          <div>
            <div style={{fontSize:13,fontWeight:700,letterSpacing:2,
              background:"linear-gradient(90deg,#a78bfa,#f472b6)",
              WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent"
            }}>NEUROSPLOIT</div>
            <div style={{fontSize:8,color:"#ffffff20",letterSpacing:2.5,marginTop:1}}>BY MAEITSEC</div>
          </div>
        </div>

        {/* Divider */}
        <div style={{width:1,height:24,background:"#ffffff0a",flexShrink:0}}/>

        {/* Target */}
        <div style={{
          display:"flex",alignItems:"center",gap:8,flex:1,
          background:"#ffffff05",border:"1px solid #ffffff0a",
          borderRadius:7,padding:"0 12px",height:32,maxWidth:340
        }}>
          <span style={{fontSize:11,color:"#ffffff20",flexShrink:0}}>TARGET</span>
          <input
            value={target} onChange={e=>setTarget(e.target.value)}
            placeholder="example.com"
            style={{
              flex:1,background:"transparent",border:"none",outline:"none",
              color:"#e2e8f0",fontSize:12,fontFamily:"inherit"
            }}
          />
          {target && (
            <div style={{width:6,height:6,borderRadius:"50%",background:"#22c55e",flexShrink:0,
              animation:"pulse-dot 2s infinite",boxShadow:"0 0 5px #22c55e88"}}/>
          )}
        </div>

        {/* Status */}
        <div style={{
          display:"flex",alignItems:"center",gap:8,padding:"0 12px",height:32,
          background:"#ffffff05",border:"1px solid #ffffff0a",borderRadius:7,flexShrink:0
        }}>
          <StatusDot ok={finHealth}/>
          {health?.claude && (
            <>
              <div style={{width:1,height:14,background:"#ffffff0a"}}/>
              <span style={{fontSize:9,color:"#ffffff25",letterSpacing:.8}}>CLAUDE CODE</span>
              <div style={{width:6,height:6,borderRadius:"50%",background:"#22c55e",
                animation:"pulse-dot 2s infinite",boxShadow:"0 0 5px #22c55e88"}}/>
            </>
          )}
        </div>

        {/* Scan count */}
        <div style={{marginLeft:"auto",flexShrink:0}}>
          <span style={{fontSize:10,color:"#ffffff20"}}>{allResults.length} scans</span>
        </div>
      </div>

      {/* ── Skills bar ── */}
      <div style={{
        background:"#050514",borderBottom:"1px solid #ffffff08",
        padding:"0 20px",height:40,display:"flex",alignItems:"center",gap:6,
        overflowX:"auto",flexShrink:0
      }}>
        {SKILLS.map(s=>(
          <button key={s.id} title={s.desc} className="sk-btn"
            onClick={()=>{
              if (!target) { push("assistant","Set a target first."); return; }
              const domain = target.replace(/https?:\/\//,"").split("/")[0];
              const body   = s.endpoint?.includes("recon")||s.endpoint?.includes("cloud") ? {domain} : {target};
              if (s.endpoint) runSkill(s.id,body);
              else push("assistant",s.label+" requires prior findings. Run recon and vuln scans first.");
            }}
            style={{
              display:"flex",alignItems:"center",gap:5,padding:"0 11px",height:26,borderRadius:5,
              border:"1px solid "+s.border,background:s.bg,color:s.color,
              fontSize:10,fontWeight:700,letterSpacing:.8,whiteSpace:"nowrap",cursor:"pointer"
            }}
          >
            <span style={{width:4,height:4,borderRadius:"50%",background:s.color,flexShrink:0}}/>
            {s.label.toUpperCase()}
          </button>
        ))}

        <div style={{width:1,height:20,background:"#ffffff0a",margin:"0 4px",flexShrink:0}}/>

        <button className="sk-btn"
          onClick={triggerFullChain}
          style={{
            display:"flex",alignItems:"center",gap:6,padding:"0 14px",height:26,borderRadius:5,
            border:"1px solid #7c3aed55",background:"linear-gradient(90deg,#7c3aed22,#db277722)",
            color:"#c084fc",fontSize:10,fontWeight:700,letterSpacing:.8,whiteSpace:"nowrap",cursor:"pointer"
          }}
        >
          <span style={{fontSize:12}}>⚡</span> FULL CHAIN
        </button>
      </div>

      {/* ── Tabs ── */}
      <div style={{
        background:"#050514",borderBottom:"1px solid #ffffff08",
        padding:"0 20px",display:"flex",alignItems:"center",gap:0,flexShrink:0,height:36
      }}>
        {TABS.map(t=>(
          <button key={t} className="tab-btn" onClick={()=>setTab(t)} style={{
            padding:"0 16px",height:"100%",background:"transparent",border:"none",
            borderBottom:tab===t?"2px solid #7c3aed":"2px solid transparent",
            color:tab===t?"#a78bfa":"#ffffff25",fontSize:10,fontWeight:700,
            letterSpacing:1.2,cursor:"pointer",textTransform:"uppercase",
            transition:"color .15s"
          }}>
            {t}
            {t==="results"&&allResults.length>0?<span style={{marginLeft:5,background:"#7c3aed33",color:"#a78bfa",padding:"1px 5px",borderRadius:3,fontSize:9}}>{allResults.length}</span>:""}
            {t==="logs"&&logs.length>0?<span style={{marginLeft:5,background:"#ffffff0a",color:"#ffffff30",padding:"1px 5px",borderRadius:3,fontSize:9}}>{logs.length}</span>:""}
          </button>
        ))}
      </div>

      {/* ── Chat tab ── */}
      {tab==="chat" && (
        <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
          {health&&!health.ok && (
            <div style={{
              margin:"12px 20px 0",padding:"10px 14px",
              background:"#ef444410",border:"1px solid #ef444430",borderRadius:8,flexShrink:0
            }}>
              <div style={{fontSize:12,color:"#ef4444",fontWeight:700,marginBottom:3}}>Backend offline</div>
              <div style={{fontSize:11,color:"#ffffff50",fontFamily:"monospace"}}>
                cd ~/AI_Pentesting/claude-code-pentest/backend && python app.py
              </div>
            </div>
          )}

          <div style={{flex:1,overflowY:"auto",padding:"16px 20px 8px"}}>
            {messages.map((m,i)=><Bubble key={i} msg={m}/>)}
            <div ref={bottomRef}/>
          </div>

          {/* Quick action pills */}
          <div style={{padding:"0 20px 8px",display:"flex",gap:5,flexWrap:"wrap",flexShrink:0}}>
            {QUICK.map(q=>(
              <button key={q.mod} className="quick-btn"
                onClick={()=>runSkill("lhf-toolkit",{target,module:q.mod})}
                style={{
                  fontSize:10,padding:"3px 10px",borderRadius:4,cursor:"pointer",
                  background:"#ffffff06",border:"1px solid #ffffff0a",
                  color:"#ffffff30",letterSpacing:.5,fontFamily:"inherit"
                }}>{q.label}</button>
            ))}
            <button className="quick-btn"
              onClick={()=>runSkill("recon-dominator",{domain:target.replace(/https?:\/\//,"").split("/")[0]})}
              style={{fontSize:10,padding:"3px 10px",borderRadius:4,cursor:"pointer",background:"#ffffff06",border:"1px solid #ffffff0a",color:"#ffffff30",letterSpacing:.5,fontFamily:"inherit"}}
            >Recon</button>
          </div>

          {/* Input */}
          <div style={{padding:"0 20px 16px",display:"flex",gap:8,flexShrink:0}}>
            <div style={{
              flex:1,display:"flex",alignItems:"center",gap:8,
              background:"#0d0d20",border:"1px solid #ffffff0f",borderRadius:9,
              padding:"0 14px",transition:"border-color .15s"
            }}
              onFocus={e=>e.currentTarget.style.borderColor="#7c3aed44"}
              onBlur={e=>e.currentTarget.style.borderColor="#ffffff0f"}
            >
              <input
                ref={inputRef} value={input} onChange={e=>setInput(e.target.value)}
                disabled={loading}
                onKeyDown={e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();handleInput();}}}
                placeholder={target?"Assess "+target+"...":"Set a target, then describe what to test..."}
                style={{
                  flex:1,background:"transparent",border:"none",outline:"none",
                  color:"#e2e8f0",fontSize:13,padding:"10px 0",fontFamily:"inherit"
                }}
              />
              {loading && <Dots/>}
            </div>
            <button onClick={handleInput} disabled={loading||!input.trim()} className="send-btn"
              style={{
                width:42,height:42,borderRadius:9,border:"none",cursor:"pointer",
                background: loading||!input.trim() ? "#ffffff08" : "linear-gradient(135deg,#7c3aed,#db2777)",
                color: loading||!input.trim() ? "#ffffff20" : "#fff",
                fontSize:16,display:"flex",alignItems:"center",justifyContent:"center",
                flexShrink:0,transition:"all .15s"
              }}
            >→</button>
          </div>
        </div>
      )}

      {/* ── Results tab ── */}
      {tab==="results" && (
        <div style={{flex:1,overflowY:"auto",padding:20}}>
          {allResults.length===0 ? (
            <div style={{textAlign:"center",padding:"60px 20px",color:"#ffffff15"}}>
              <div style={{fontSize:40,marginBottom:12}}>◈</div>
              <div style={{fontSize:13,letterSpacing:1}}>No scan results yet</div>
              <div style={{fontSize:11,marginTop:6,color:"#ffffff10"}}>Run a module from the chat tab</div>
            </div>
          ) : (
            allResults.map((m,i)=>{
              const sk = SKILLS.find(s=>s.id===m.skill);
              return (
                <div key={i} style={{marginBottom:14}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
                    <div style={{width:6,height:6,borderRadius:"50%",background:sk?.color||"#a78bfa"}}/>
                    <span style={{fontSize:10,fontWeight:700,color:sk?.color||"#a78bfa",letterSpacing:.8}}>{m.skill}</span>
                    <span style={{fontSize:10,color:"#ffffff25"}}>{m.result?.target||m.result?.domain}</span>
                    <span style={{fontSize:10,color:"#ffffff15",marginLeft:"auto"}}>{m.result?.duration}s</span>
                  </div>
                  <div style={{background:"#0a0a1a",border:"1px solid #ffffff0a",borderRadius:8,padding:"12px 14px",maxHeight:300,overflowY:"auto"}}>
                    <pre style={{fontSize:11,color:"#64748b",whiteSpace:"pre-wrap",lineHeight:1.65,fontFamily:"'JetBrains Mono',monospace"}}>
                      {stripAnsi(m.result?.output||JSON.stringify(m.result,null,2))}
                    </pre>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* ── Logs tab ── */}
      {tab==="logs" && (
        <div style={{flex:1,overflowY:"auto",padding:20}}>
          {logs.length===0 ? (
            <div style={{textAlign:"center",padding:"60px 20px",color:"#ffffff15"}}>
              <div style={{fontSize:40,marginBottom:12}}>◈</div>
              <div style={{fontSize:13,letterSpacing:1}}>No activity yet</div>
            </div>
          ) : (
            <div style={{fontFamily:"'JetBrains Mono',monospace"}}>
              {logs.map((l,i)=>{
                const sk = SKILLS.find(s=>s.id===l.skill);
                const tc = l.type==="error"?"#ef4444":l.type==="done"?"#22c55e":"#a78bfa";
                return (
                  <div key={i} style={{
                    display:"flex",gap:10,padding:"5px 0",
                    borderBottom:"1px solid #ffffff05",alignItems:"center"
                  }}>
                    <span style={{fontSize:10,color:"#ffffff15",flexShrink:0,minWidth:70}}>{l.time}</span>
                    <span style={{width:6,height:6,borderRadius:"50%",background:tc,flexShrink:0}}/>
                    <span style={{fontSize:10,fontWeight:700,color:tc,flexShrink:0,minWidth:40,letterSpacing:.5}}>{l.type.toUpperCase()}</span>
                    <span style={{fontSize:10,color:sk?.color||"#a78bfa",flexShrink:0}}>{l.skill}</span>
                    <span style={{fontSize:10,color:"#ffffff25",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{l.target||l.error}</span>
                    {l.duration&&<span style={{fontSize:10,color:"#ffffff15",marginLeft:"auto",flexShrink:0}}>{l.duration}s</span>}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
