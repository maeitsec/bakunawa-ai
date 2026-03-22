import { useState, useRef, useEffect } from "react";

const API = "http://localhost:5000";

const SKILLS = [
  { id:"lhf-toolkit",           label:"LHF Checks",  icon:"⬡", color:"#38bdf8", endpoint:"/scan/lhf",    desc:"Headers · DNS · CORS · Info Disclosure", tag:"RECON" },
  { id:"recon-dominator",       label:"Recon",        icon:"◎", color:"#a78bfa", endpoint:"/scan/recon",  desc:"Subdomain enum · Port scan · OSINT",      tag:"RECON" },
  { id:"webapp-exploit-hunter", label:"WebApp",       icon:"◈", color:"#fb923c", endpoint:"/scan/webapp", desc:"SQLi · XSS · SSRF · IDOR · SSTI",         tag:"EXPLOIT" },
  { id:"api-breaker",           label:"API",          icon:"◇", color:"#f472b6", endpoint:"/scan/api",    desc:"BOLA · JWT · GraphQL · Mass Assignment",  tag:"EXPLOIT" },
  { id:"cloud-pivot-finder",    label:"Cloud",        icon:"◉", color:"#34d399", endpoint:"/scan/cloud",  desc:"S3 · Takeover · CI/CD · Serverless",      tag:"PIVOT" },
  { id:"attack-path-architect", label:"Attack Paths", icon:"◆", color:"#fbbf24", endpoint:null,           desc:"MITRE ATT&CK · Kill Chains",              tag:"ANALYZE" },
  { id:"vuln-chain-composer",   label:"Chain",        icon:"◗", color:"#f87171", endpoint:null,           desc:"Exploit Chains · Bug Bounty Reports",     tag:"REPORT" },
];

const QUICK_SCANS = [
  { label:"Security Headers", skill:"lhf-toolkit",     body:{module:"headers"}, color:"#38bdf8" },
  { label:"DNS Recon",        skill:"lhf-toolkit",     body:{module:"dns"},     color:"#a78bfa" },
  { label:"CORS Check",       skill:"lhf-toolkit",     body:{module:"cors"},    color:"#34d399" },
  { label:"Info Disclosure",  skill:"lhf-toolkit",     body:{module:"info"},    color:"#f472b6" },
  { label:"Full LHF Scan",    skill:"lhf-toolkit",     body:{module:"all"},     color:"#fbbf24" },
  { label:"Subdomain Recon",  skill:"recon-dominator", body:{},                 color:"#fb923c" },
];

const stripAnsi = s => typeof s==="string" ? s.replace(/\x1b\[[0-9;]*m/g,"") : JSON.stringify(s,null,2);

function App() {
  const [target,  setTarget]  = useState("");
  const [input,   setInput]   = useState("");
  const [msgs,    setMsgs]    = useState([]);
  const [loading, setLoading] = useState(false);
  const [health,  setHealth]  = useState(null);
  const [logs,    setLogs]    = useState([]);
  const [results, setResults] = useState([]);
  const [view,    setView]    = useState("chat");
  const [openRes, setOpenRes] = useState(null);
  const bottom   = useRef();
  const inputRef = useRef();

  useEffect(()=>{ bottom.current?.scrollIntoView({behavior:"smooth"}); },[msgs]);
  useEffect(()=>{
    fetch(API+"/health").then(r=>r.json()).then(d=>setHealth({ok:true,...d})).catch(()=>setHealth({ok:false}));
  },[]);

  const addLog  = e  => setLogs(p=>[{...e,t:new Date().toLocaleTimeString()},...p].slice(0,100));
  const pushBot = (text,extra={}) => setMsgs(p=>[...p,{role:"bot",text,...extra}]);
  const pushUser = text => setMsgs(p=>[...p,{role:"user",text}]);

  const runSkill = async (sid, bodyExtra={}) => {
    const sk = SKILLS.find(s=>s.id===sid);
    if (!sk?.endpoint) { pushBot(sk?.label+" requires prior scan findings."); return; }
    if (!target)       { pushBot("Set a target domain first."); return; }
    const domain = target.replace(/https?:\/\//,"").split("/")[0];
    const body   = sid==="recon-dominator"||sid==="cloud-pivot-finder"
      ? {domain,...bodyExtra} : {target,...bodyExtra};

    setLoading(true);
    setMsgs(p=>[...p,{role:"bot",text:"",loading:true,skill:sid}]);
    addLog({type:"START",skill:sid,target:body.target||body.domain});

    try {
      const r = await fetch(API+sk.endpoint,{
        method:"POST", headers:{"Content-Type":"application/json"},
        body:JSON.stringify(body), signal:AbortSignal.timeout(180000)
      });
      const d = await r.json();
      const result = {...d,skill:sid,ts:new Date().toLocaleTimeString()};
      setMsgs(p=>[...p.slice(0,-1),{role:"bot",text:`Scan complete in ${d.duration||"?"}s`,result,skill:sid}]);
      setResults(p=>[result,...p]);
      addLog({type:"DONE",skill:sid,target:body.target||body.domain,dur:d.duration});
    } catch(e) {
      setMsgs(p=>[...p.slice(0,-1),{role:"bot",text:"Backend unreachable.\nRun: python app.py"}]);
      addLog({type:"ERR",skill:sid,err:e.message});
    }
    setLoading(false);
  };

  const handleSend = () => {
    if (!input.trim()||loading) return;
    const txt = input.trim(); pushUser(txt); setInput("");
    const low = txt.toLowerCase();
    const t   = target||(txt.match(/(?:on|test|scan)\s+([\w.\-]+\.\w+)/i)||[])[1]||"";
    if (!t) { pushBot("What target should I assess?"); return; }
    if (!target&&t) setTarget(t);
    if      (low.match(/full|all/))        runSkill("lhf-toolkit",{module:"all"});
    else if (low.match(/header/))          runSkill("lhf-toolkit",{module:"headers"});
    else if (low.match(/dns/))             runSkill("lhf-toolkit",{module:"dns"});
    else if (low.match(/cors|method/))     runSkill("lhf-toolkit",{module:"cors"});
    else if (low.match(/info|disclos/))    runSkill("lhf-toolkit",{module:"info"});
    else if (low.match(/recon|subdom/))    runSkill("recon-dominator");
    else if (low.match(/webapp|sqli|xss/)) runSkill("webapp-exploit-hunter");
    else if (low.match(/api|bola|jwt/))    runSkill("api-breaker");
    else if (low.match(/cloud|s3/))        runSkill("cloud-pivot-finder");
    else pushBot(`Available assessments for ${t}:\n\n→ Security Headers\n→ DNS Reconnaissance\n→ HTTP Methods & CORS\n→ Information Disclosure\n→ Subdomain Recon\n→ Web App Vulnerabilities\n→ API Security\n→ Cloud Infrastructure\n→ Full Chain (all modules)\n\nWhat would you like?`);
  };

  const fullChain = () => {
    if (!target) { pushBot("Set a target first."); return; }
    const domain = target.replace(/https?:\/\//,"").split("/")[0];
    [{id:"lhf-toolkit",b:{module:"all"}},{id:"recon-dominator",b:{}},
     {id:"webapp-exploit-hunter",b:{}},{id:"api-breaker",b:{}},{id:"cloud-pivot-finder",b:{}}]
      .forEach((s,i)=>setTimeout(()=>runSkill(s.id,s.b),i*3500));
  };

  const ok = health?.ok;

  /* ─────────────── RENDER ─────────────── */
  return (
    <div style={{display:"flex",flexDirection:"column",height:"100vh",background:"#07080f",color:"#e2e8f0",fontFamily:"Inter,-apple-system,sans-serif",overflow:"hidden"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}
        ::-webkit-scrollbar{width:3px;height:3px}
        ::-webkit-scrollbar-thumb{background:#ffffff15;border-radius:99px}
        ::-webkit-scrollbar-track{background:transparent}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
        @keyframes spin{to{transform:rotate(360deg)}}
        @keyframes slideup{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
        @keyframes snakeit{0%{transform:scaleX(1)}50%{transform:scaleX(.92) scaleY(1.06)}100%{transform:scaleX(1)}}
        input:focus{outline:none} button{cursor:pointer;font-family:inherit}
      `}</style>

      {/* ══════════════ TOP BAR ══════════════ */}
      <div style={{
        height:58,background:"#0b0c18",borderBottom:"1px solid rgba(255,255,255,.06)",
        display:"flex",alignItems:"center",padding:"0 20px",gap:14,flexShrink:0,
        boxShadow:"0 2px 20px rgba(0,0,0,.5)"
      }}>

        {/* ── Brand ── */}
        <div style={{display:"flex",alignItems:"center",gap:10,flexShrink:0}}>
          {/* Snake logo mark */}
          <div style={{
            width:36,height:36,borderRadius:10,
            background:"linear-gradient(135deg,#10b981 0%,#059669 50%,#065f46 100%)",
            display:"flex",alignItems:"center",justifyContent:"center",
            fontSize:20,animation:"snakeit 4s ease-in-out infinite",
            boxShadow:"0 0 16px rgba(16,185,129,.45),0 0 32px rgba(16,185,129,.15)"
          }}>🐍</div>
          <div>
            <div style={{
              fontSize:15,fontWeight:800,letterSpacing:1.5,
              background:"linear-gradient(90deg,#10b981,#34d399,#6ee7b7)",
              WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent",
              fontFamily:"'JetBrains Mono',monospace"
            }}>BakunawaAI</div>
            <div style={{fontSize:8,color:"rgba(255,255,255,.22)",letterSpacing:2.2,fontFamily:"'JetBrains Mono',monospace",marginTop:1}}>
              AI-POWERED PENETRATION TESTING · BY MAEITSEC
            </div>
          </div>
        </div>

        <div style={{width:1,height:28,background:"rgba(255,255,255,.07)",flexShrink:0}}/>

        {/* ── Target ── */}
        <div style={{
          display:"flex",alignItems:"center",gap:8,flex:1,maxWidth:400,height:36,
          background:"rgba(255,255,255,.04)",border:"1px solid rgba(255,255,255,.08)",
          borderRadius:8,padding:"0 12px",transition:"all .2s"
        }}
          onFocusCapture={e=>{e.currentTarget.style.borderColor="rgba(16,185,129,.5)";e.currentTarget.style.boxShadow="0 0 0 3px rgba(16,185,129,.1)";}}
          onBlurCapture={e=>{e.currentTarget.style.borderColor="rgba(255,255,255,.08)";e.currentTarget.style.boxShadow="none";}}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,.2)" strokeWidth="2">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/>
          </svg>
          <input value={target} onChange={e=>setTarget(e.target.value)}
            placeholder="Enter target domain..."
            style={{flex:1,background:"transparent",border:"none",color:"#e2e8f0",fontSize:13,fontFamily:"'JetBrains Mono',monospace"}}
          />
          {target&&(
            <span style={{
              fontSize:9,fontWeight:700,padding:"2px 7px",borderRadius:3,flexShrink:0,
              background:"rgba(16,185,129,.15)",color:"#10b981",letterSpacing:.8,
              border:"1px solid rgba(16,185,129,.3)",animation:"pulse 2s infinite",
              fontFamily:"'JetBrains Mono',monospace"
            }}>ACTIVE</span>
          )}
        </div>

        {/* ── Right: status + stats ── */}
        <div style={{marginLeft:"auto",display:"flex",alignItems:"center",gap:8,flexShrink:0}}>
          <div style={{
            display:"flex",alignItems:"center",gap:6,padding:"0 12px",height:32,
            background:"rgba(255,255,255,.03)",border:"1px solid rgba(255,255,255,.06)",borderRadius:7
          }}>
            <div style={{
              width:7,height:7,borderRadius:"50%",
              background:health===null?"#6b7280":ok?"#10b981":"#ef4444",
              boxShadow:ok?"0 0 8px #10b98188":"none",
              animation:ok?"pulse 2s infinite":"none"
            }}/>
            <span style={{
              fontSize:10,fontWeight:700,letterSpacing:.8,
              color:health===null?"#6b7280":ok?"#10b981":"#ef4444",
              fontFamily:"'JetBrains Mono',monospace"
            }}>{health===null?"INIT":ok?"ONLINE":"OFFLINE"}</span>
            {ok&&<>
              <div style={{width:1,height:12,background:"rgba(255,255,255,.08)"}}/>
              <span style={{fontSize:9,color:"rgba(255,255,255,.25)",fontFamily:"'JetBrains Mono',monospace"}}>Claude Code</span>
              <div style={{width:5,height:5,borderRadius:"50%",background:"#10b981",boxShadow:"0 0 6px #10b981",animation:"pulse 2s infinite"}}/>
            </>}
          </div>
          {[["SCANS",results.length,"#10b981"],["LOGS",logs.length,"#38bdf8"]].map(([l,v,c])=>(
            <div key={l} style={{textAlign:"center",padding:"4px 12px",background:"rgba(255,255,255,.03)",border:"1px solid rgba(255,255,255,.06)",borderRadius:7}}>
              <div style={{fontSize:14,fontWeight:700,color:c,fontFamily:"'JetBrains Mono',monospace",lineHeight:1}}>{v}</div>
              <div style={{fontSize:7,color:"rgba(255,255,255,.2)",letterSpacing:1,marginTop:1}}>{l}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ══════════════ BODY ══════════════ */}
      <div style={{flex:1,display:"flex",overflow:"hidden"}}>

        {/* ── SIDEBAR ── */}
        <div style={{
          width:224,background:"#0a0b17",borderRight:"1px solid rgba(255,255,255,.06)",
          display:"flex",flexDirection:"column",flexShrink:0,overflow:"hidden"
        }}>
          <div style={{flex:1,overflowY:"auto",padding:"12px 10px 0"}}>
            <div style={{fontSize:8,fontWeight:700,color:"rgba(255,255,255,.18)",letterSpacing:2,padding:"0 6px 8px",fontFamily:"'JetBrains Mono',monospace"}}>MODULES</div>

            {SKILLS.map(s=>(
              <button key={s.id}
                onClick={()=>{
                  if (!target) { pushBot("Set a target first."); return; }
                  if (s.endpoint) runSkill(s.id);
                  else pushBot(s.label+" requires prior scan data. Run Recon first.");
                }}
                style={{
                  width:"100%",display:"flex",alignItems:"center",gap:9,padding:"7px 8px",
                  borderRadius:7,border:"none",background:"transparent",color:"rgba(255,255,255,.55)",
                  marginBottom:2,textAlign:"left",transition:"all .15s"
                }}
                onMouseEnter={e=>{e.currentTarget.style.background=`${s.color}14`;e.currentTarget.style.color=s.color;}}
                onMouseLeave={e=>{e.currentTarget.style.background="transparent";e.currentTarget.style.color="rgba(255,255,255,.55)";}}
              >
                <div style={{
                  width:30,height:30,borderRadius:7,flexShrink:0,
                  background:`${s.color}14`,border:`1px solid ${s.color}28`,
                  display:"flex",alignItems:"center",justifyContent:"center",
                  fontSize:13,color:s.color
                }}>{s.icon}</div>
                <div style={{minWidth:0}}>
                  <div style={{fontSize:12,fontWeight:600,lineHeight:1.2}}>{s.label}</div>
                  <div style={{fontSize:9,color:"rgba(255,255,255,.22)",marginTop:2,letterSpacing:.3}}>{s.tag}</div>
                </div>
              </button>
            ))}

            <div style={{margin:"10px 6px",height:1,background:"rgba(255,255,255,.06)"}}/>

            {/* Full chain */}
            <button onClick={fullChain} style={{
              width:"100%",display:"flex",alignItems:"center",gap:9,padding:"7px 8px",
              borderRadius:7,border:"1px solid rgba(16,185,129,.25)",
              background:"rgba(16,185,129,.08)",color:"#10b981",
              marginBottom:10,textAlign:"left",transition:"all .15s"
            }}
              onMouseEnter={e=>{e.currentTarget.style.background="rgba(16,185,129,.16)";e.currentTarget.style.borderColor="rgba(16,185,129,.4)";}}
              onMouseLeave={e=>{e.currentTarget.style.background="rgba(16,185,129,.08)";e.currentTarget.style.borderColor="rgba(16,185,129,.25)";}}
            >
              <div style={{width:30,height:30,borderRadius:7,flexShrink:0,background:"rgba(16,185,129,.15)",border:"1px solid rgba(16,185,129,.35)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14}}>⚡</div>
              <div>
                <div style={{fontSize:12,fontWeight:700,letterSpacing:.3}}>Full Chain</div>
                <div style={{fontSize:9,color:"rgba(16,185,129,.5)",marginTop:2}}>Run all modules</div>
              </div>
            </button>
          </div>

          {/* Quick scan grid */}
          <div style={{borderTop:"1px solid rgba(255,255,255,.06)",padding:"10px"}}>
            <div style={{fontSize:8,fontWeight:700,color:"rgba(255,255,255,.18)",letterSpacing:2,marginBottom:8,fontFamily:"'JetBrains Mono',monospace"}}>QUICK SCAN</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:4}}>
              {QUICK_SCANS.map(q=>(
                <button key={q.label} onClick={()=>runSkill(q.skill,q.body)} style={{
                  padding:"5px 7px",borderRadius:5,border:`1px solid ${q.color}20`,
                  background:`${q.color}08`,color:q.color,fontSize:9,fontWeight:600,
                  textAlign:"left",lineHeight:1.3,transition:"all .15s"
                }}
                  onMouseEnter={e=>{e.currentTarget.style.background=`${q.color}1a`;e.currentTarget.style.borderColor=`${q.color}40`;}}
                  onMouseLeave={e=>{e.currentTarget.style.background=`${q.color}08`;e.currentTarget.style.borderColor=`${q.color}20`;}}
                >{q.label}</button>
              ))}
            </div>
          </div>
        </div>

        {/* ── MAIN PANEL ── */}
        <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>

          {/* Tab bar */}
          <div style={{
            height:38,background:"#0a0b17",borderBottom:"1px solid rgba(255,255,255,.06)",
            display:"flex",alignItems:"center",padding:"0 16px",gap:2,flexShrink:0
          }}>
            {[["chat","Chat"],["results",`Results${results.length?` (${results.length})`:""}`],["logs",`Logs${logs.length?` (${logs.length})`:""}`]].map(([id,lbl])=>(
              <button key={id} onClick={()=>setView(id)} style={{
                padding:"0 14px",height:28,borderRadius:6,border:"none",
                background:view===id?"rgba(16,185,129,.15)":"transparent",
                color:view===id?"#10b981":"rgba(255,255,255,.28)",
                fontSize:11,fontWeight:600,letterSpacing:.5,transition:"all .15s",
                fontFamily:"'JetBrains Mono',monospace"
              }}>{lbl.toUpperCase()}</button>
            ))}
          </div>

          {/* ── CHAT ── */}
          {view==="chat"&&(
            <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>

              {/* Welcome */}
              {msgs.length===0&&(
                <div style={{flex:1,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",padding:40,gap:20,animation:"slideup .4s ease"}}>
                  <div style={{
                    width:80,height:80,borderRadius:20,fontSize:38,
                    background:"linear-gradient(135deg,#065f46,#059669,#10b981)",
                    display:"flex",alignItems:"center",justifyContent:"center",
                    boxShadow:"0 0 40px rgba(16,185,129,.4),0 0 80px rgba(16,185,129,.12)",
                    animation:"snakeit 4s ease-in-out infinite"
                  }}>🐍</div>
                  <div style={{textAlign:"center"}}>
                    <div style={{
                      fontSize:26,fontWeight:800,letterSpacing:1,marginBottom:6,
                      background:"linear-gradient(90deg,#10b981,#34d399,#6ee7b7)",
                      WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent",
                      fontFamily:"'JetBrains Mono',monospace"
                    }}>BakunawaAI</div>
                    <div style={{fontSize:13,color:"rgba(255,255,255,.35)",lineHeight:1.7,maxWidth:400}}>
                      AI-Powered Penetration Testing.<br/>
                      Set your target and select a module — or describe what you want to test.
                    </div>
                    <div style={{marginTop:8,fontSize:10,color:"rgba(255,255,255,.15)",fontFamily:"'JetBrains Mono',monospace"}}>
                      ⚠ Authorized testing only · Built by @maeitsec
                    </div>
                  </div>

                  <div style={{display:"flex",flexWrap:"wrap",gap:7,justifyContent:"center",maxWidth:480}}>
                    {["Claude Code Powered","7 Skill Modules","43 Python Scripts","Zero pip deps","Bug Bounty Ready","Philippine-built"].map(f=>(
                      <span key={f} style={{
                        fontSize:10,padding:"4px 12px",borderRadius:20,
                        background:"rgba(16,185,129,.07)",border:"1px solid rgba(16,185,129,.15)",
                        color:"rgba(16,185,129,.7)",fontFamily:"'JetBrains Mono',monospace"
                      }}>{f}</span>
                    ))}
                  </div>

                  {!target&&(
                    <div style={{display:"flex",alignItems:"center",gap:8,padding:"10px 18px",background:"rgba(16,185,129,.06)",border:"1px solid rgba(16,185,129,.18)",borderRadius:8}}>
                      <span style={{fontSize:12,color:"rgba(16,185,129,.6)"}}>↑ Enter a target domain in the top bar to begin</span>
                    </div>
                  )}
                </div>
              )}

              {/* Messages */}
              {msgs.length>0&&(
                <div style={{flex:1,overflowY:"auto",padding:"16px 20px 8px"}}>
                  {msgs.map((m,i)=>{
                    const sk = SKILLS.find(s=>s.id===m.skill);
                    return(
                      <div key={i} style={{display:"flex",justifyContent:m.role==="user"?"flex-end":"flex-start",marginBottom:12,gap:8,alignItems:"flex-start",animation:"slideup .2s ease"}}>
                        {m.role==="bot"&&(
                          <div style={{
                            width:26,height:26,borderRadius:7,flexShrink:0,marginTop:2,fontSize:14,
                            background:"linear-gradient(135deg,#065f46,#10b981)",
                            display:"flex",alignItems:"center",justifyContent:"center",
                            boxShadow:"0 2px 8px rgba(16,185,129,.35)"
                          }}>🐍</div>
                        )}
                        <div style={{maxWidth:"78%",minWidth:0}}>
                          {m.role==="bot"&&<div style={{fontSize:8,color:"rgba(255,255,255,.2)",marginBottom:3,fontWeight:700,letterSpacing:2,fontFamily:"'JetBrains Mono',monospace"}}>BAKUNAWA AI</div>}
                          <div style={{
                            padding:"10px 14px",fontSize:13,lineHeight:1.75,color:"#e2e8f0",whiteSpace:"pre-wrap",
                            background:m.role==="user"?"rgba(16,185,129,.12)":"rgba(255,255,255,.04)",
                            border:`1px solid ${m.role==="user"?"rgba(16,185,129,.25)":"rgba(255,255,255,.07)"}`,
                            borderRadius:m.role==="user"?"12px 3px 12px 12px":"3px 12px 12px 12px"
                          }}>
                            {m.loading?(
                              <div style={{display:"flex",gap:5,alignItems:"center"}}>
                                {[0,1,2].map(j=><div key={j} style={{width:5,height:5,borderRadius:"50%",background:"#10b981",animation:`pulse 1.2s ${j*.2}s infinite`}}/>)}
                                <span style={{fontSize:11,color:"rgba(255,255,255,.3)",marginLeft:4,fontFamily:"'JetBrains Mono',monospace"}}>Running {sk?.label||"scan"}...</span>
                              </div>
                            ):m.text}
                          </div>
                          {m.result&&(
                            <div style={{marginTop:8,background:"rgba(255,255,255,.03)",border:`1px solid ${sk?.color||"#10b981"}20`,borderRadius:8,overflow:"hidden"}}>
                              <div onClick={()=>setOpenRes(openRes===i?null:i)} style={{display:"flex",alignItems:"center",gap:8,padding:"8px 12px",cursor:"pointer",background:`${sk?.color||"#10b981"}08`}}>
                                <div style={{width:6,height:6,borderRadius:"50%",background:sk?.color||"#10b981",boxShadow:`0 0 6px ${sk?.color||"#10b981"}`}}/>
                                <span style={{fontSize:10,fontWeight:700,color:sk?.color||"#10b981",letterSpacing:.8,fontFamily:"'JetBrains Mono',monospace",flex:1}}>{m.result.skill}</span>
                                <span style={{fontSize:10,color:"rgba(255,255,255,.2)",fontFamily:"'JetBrains Mono',monospace"}}>{m.result.duration}s</span>
                                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,.25)" strokeWidth="2.5" style={{transform:openRes===i?"rotate(180deg)":"none",transition:"transform .2s"}}><polyline points="6 9 12 15 18 9"/></svg>
                              </div>
                              {openRes===i&&(
                                <div style={{maxHeight:320,overflowY:"auto",padding:"10px 12px",borderTop:`1px solid ${sk?.color||"#10b981"}15`}}>
                                  <pre style={{fontSize:11,color:"#64748b",whiteSpace:"pre-wrap",lineHeight:1.7,fontFamily:"'JetBrains Mono',monospace"}}>
                                    {stripAnsi(m.result.output||JSON.stringify(m.result,null,2))}
                                  </pre>
                                </div>
                              )}
                            </div>
                          )}
                          {m.skill&&(()=>{
                            const sk2=SKILLS.find(s=>s.id===m.skill);
                            return sk2?<span style={{display:"inline-block",marginTop:5,fontSize:9,padding:"2px 8px",borderRadius:3,fontWeight:700,letterSpacing:.8,background:`${sk2.color}14`,color:sk2.color,border:`1px solid ${sk2.color}28`,fontFamily:"'JetBrains Mono',monospace"}}>{sk2.id}</span>:null;
                          })()}
                        </div>
                      </div>
                    );
                  })}
                  <div ref={bottom}/>
                </div>
              )}

              {/* Input */}
              <div style={{padding:"10px 20px 16px",flexShrink:0,borderTop:"1px solid rgba(255,255,255,.05)"}}>
                <div style={{
                  display:"flex",gap:8,alignItems:"center",
                  background:"rgba(255,255,255,.04)",border:"1px solid rgba(255,255,255,.09)",
                  borderRadius:10,padding:"4px 4px 4px 14px",transition:"all .2s"
                }}
                  onFocusCapture={e=>{e.currentTarget.style.borderColor="rgba(16,185,129,.4)";e.currentTarget.style.boxShadow="0 0 0 3px rgba(16,185,129,.07)";}}
                  onBlurCapture={e=>{e.currentTarget.style.borderColor="rgba(255,255,255,.09)";e.currentTarget.style.boxShadow="none";}}
                >
                  <input ref={inputRef} value={input} onChange={e=>setInput(e.target.value)} disabled={loading}
                    onKeyDown={e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();handleSend();}}}
                    placeholder={target?`Assess ${target}...`:"Set target above, then describe what to test..."}
                    style={{flex:1,background:"transparent",border:"none",color:"#e2e8f0",fontSize:13,padding:"8px 0"}}
                  />
                  <button onClick={handleSend} disabled={loading||!input.trim()} style={{
                    width:36,height:36,borderRadius:8,border:"none",flexShrink:0,
                    display:"flex",alignItems:"center",justifyContent:"center",transition:"all .2s",
                    background:loading||!input.trim()?"rgba(255,255,255,.05)":"linear-gradient(135deg,#059669,#10b981)",
                    color:loading||!input.trim()?"rgba(255,255,255,.2)":"#fff",
                    boxShadow:loading||!input.trim()?"none":"0 2px 10px rgba(16,185,129,.4)"
                  }}>
                    {loading
                      ?<div style={{width:14,height:14,borderRadius:"50%",border:"2px solid rgba(255,255,255,.15)",borderTopColor:"#10b981",animation:"spin .7s linear infinite"}}/>
                      :<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg>
                    }
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ── RESULTS ── */}
          {view==="results"&&(
            <div style={{flex:1,overflowY:"auto",padding:20}}>
              {results.length===0?(
                <div style={{textAlign:"center",padding:"80px 20px",animation:"slideup .3s ease"}}>
                  <div style={{fontSize:42,marginBottom:12}}>🐍</div>
                  <div style={{fontSize:13,color:"rgba(255,255,255,.2)",fontFamily:"'JetBrains Mono',monospace",letterSpacing:1}}>NO RESULTS YET</div>
                  <div style={{fontSize:11,color:"rgba(255,255,255,.1)",marginTop:6}}>Run a scan to see results here</div>
                </div>
              ):results.map((r,i)=>{
                const sk=SKILLS.find(s=>s.id===r.skill);
                return(
                  <div key={i} style={{border:`1px solid ${sk?.color||"#10b981"}20`,borderRadius:10,overflow:"hidden",background:`${sk?.color||"#10b981"}06`,marginBottom:10}}>
                    <div onClick={()=>setOpenRes(openRes===`r${i}`?null:`r${i}`)} style={{display:"flex",alignItems:"center",gap:10,padding:"12px 16px",cursor:"pointer"}}>
                      <div style={{width:8,height:8,borderRadius:"50%",background:sk?.color||"#10b981",boxShadow:`0 0 8px ${sk?.color||"#10b981"}`}}/>
                      <span style={{fontSize:11,fontWeight:700,color:sk?.color||"#10b981",letterSpacing:.8,fontFamily:"'JetBrains Mono',monospace"}}>{r.skill}</span>
                      <span style={{fontSize:12,color:"rgba(255,255,255,.4)",flex:1}}>{r.target||r.domain}</span>
                      <span style={{fontSize:10,color:"rgba(255,255,255,.2)",fontFamily:"'JetBrains Mono',monospace"}}>{r.ts}</span>
                      <span style={{fontSize:10,color:"rgba(255,255,255,.15)",fontFamily:"'JetBrains Mono',monospace",marginLeft:8}}>{r.duration}s</span>
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,.25)" strokeWidth="2.5" style={{transform:openRes===`r${i}`?"rotate(180deg)":"none",transition:"transform .2s"}}><polyline points="6 9 12 15 18 9"/></svg>
                    </div>
                    {openRes===`r${i}`&&(
                      <div style={{borderTop:`1px solid ${sk?.color||"#10b981"}15`,padding:"12px 16px",maxHeight:400,overflowY:"auto"}}>
                        <pre style={{fontSize:11,color:"#64748b",whiteSpace:"pre-wrap",lineHeight:1.7,fontFamily:"'JetBrains Mono',monospace"}}>
                          {stripAnsi(r.output||JSON.stringify(r,null,2))}
                        </pre>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* ── LOGS ── */}
          {view==="logs"&&(
            <div style={{flex:1,overflowY:"auto",padding:20}}>
              {logs.length===0?(
                <div style={{textAlign:"center",padding:"80px 20px"}}>
                  <div style={{fontSize:42,marginBottom:12}}>🐍</div>
                  <div style={{fontSize:13,color:"rgba(255,255,255,.2)",fontFamily:"'JetBrains Mono',monospace",letterSpacing:1}}>NO ACTIVITY</div>
                </div>
              ):(
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11}}>
                  {logs.map((l,i)=>{
                    const sk=SKILLS.find(s=>s.id===l.skill);
                    const c=l.type==="ERR"?"#ef4444":l.type==="DONE"?"#10b981":"#a78bfa";
                    return(
                      <div key={i} style={{display:"flex",gap:12,padding:"5px 6px",borderRadius:5,alignItems:"center",marginBottom:1}}
                        onMouseEnter={e=>e.currentTarget.style.background="rgba(255,255,255,.03)"}
                        onMouseLeave={e=>e.currentTarget.style.background="transparent"}
                      >
                        <span style={{color:"rgba(255,255,255,.15)",minWidth:70,flexShrink:0}}>{l.t}</span>
                        <span style={{padding:"1px 6px",borderRadius:3,background:`${c}15`,color:c,border:`1px solid ${c}28`,minWidth:42,textAlign:"center",fontSize:9,fontWeight:700}}>{l.type}</span>
                        <span style={{color:sk?.color||"#10b981",minWidth:130,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{l.skill}</span>
                        <span style={{color:"rgba(255,255,255,.3)",flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{l.target||l.err}</span>
                        {l.dur&&<span style={{color:"rgba(255,255,255,.18)",flexShrink:0}}>{l.dur}s</span>}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
