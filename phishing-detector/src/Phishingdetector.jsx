import { useState, useEffect, useRef } from "react";

function validateURL(raw) {
  const url = raw.trim();
  if (!url) return { valid: false, reason: "Pray, provide a URL for examination, dear visitor." };
  const hasProtocol = /^https?:\/\//i.test(url);
  const looksLikeDomain = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+/.test(url);
  if (!hasProtocol && !looksLikeDomain)
    return { valid: false, reason: "That does not resemble a proper address. Try https://example.com" };
  let parsed;
  try { parsed = new URL(hasProtocol ? url : "https://" + url); }
  catch { return { valid: false, reason: "I could not decipher this address. Please check its form." }; }
  const hostname = parsed.hostname.toLowerCase();
  if (!/\.[a-zA-Z]{2,}$/.test(hostname))
    return { valid: false, reason: "The domain requires a proper ending, such as .com or .org" };
  if (hostname === "localhost" || hostname === "127.0.0.1" || hostname.endsWith(".local"))
    return { valid: false, reason: "That is a local address — I only examine addresses of the outside world." };
  if (!hostname || hostname.length < 3)
    return { valid: false, reason: "The domain name appears to be absent from this address." };
  return { valid: true, parsed, hostname, normalizedUrl: hasProtocol ? url : "https://" + url };
}

function validateEmail(raw) {
  const v = raw.trim();
  if (!v) return { valid: false, reason: "Please present the correspondence for my inspection." };
  if (v.length < 10) return { valid: false, reason: "This missive appears far too brief for analysis." };
  if (v.length > 5000) return { valid: false, reason: "This is an uncommonly long document. Please present only the relevant portion." };
  return { valid: true };
}

function validateSMS(raw) {
  const v = raw.trim();
  if (!v) return { valid: false, reason: "Please present the telegram for my examination." };
  if (v.length < 5) return { valid: false, reason: "This telegram is far too brief." };
  if (v.length > 2000) return { valid: false, reason: "The message exceeds acceptable length. Maximum 2000 characters." };
  return { valid: true };
}

const SAFE_DOMAINS = new Set(["google.com","youtube.com","facebook.com","twitter.com","instagram.com","linkedin.com","github.com","microsoft.com","apple.com","amazon.com","wikipedia.org","reddit.com","stackoverflow.com","anthropic.com","claude.ai","openai.com","netflix.com","spotify.com","dropbox.com","notion.so"]);

function instantScan(mode, content) {
  if (mode === "url") {
    const hasProtocol = /^https?:\/\//i.test(content);
    let parsed;
    try { parsed = new URL(hasProtocol ? content : "https://" + content); } catch { return null; }
    const hostname = parsed.hostname.toLowerCase();
    const domain = hostname.replace(/^www\./, "");
    const flags = [], goodSigns = [];
    let score = 0;
    if (parsed.protocol === "http:") { flags.push("Unencrypted HTTP connection"); score += 20; }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) { flags.push("Raw IP address used as domain"); score += 35; }
    const badTLDs = [".xyz",".tk",".ml",".ga",".cf",".gq",".top",".click",".zip",".download",".loan",".win",".racing"];
    const tld = badTLDs.find(t => hostname.endsWith(t));
    if (tld) { flags.push(`Suspicious domain suffix: ${tld}`); score += 25; }
    if (hostname.split(".").length - 2 >= 3) { flags.push("Excessive subdomain nesting"); score += 15; }
    if (hostname.length > 50) { flags.push("Unusually lengthy domain name"); score += 10; }
    const brands = ["paypal","google","amazon","facebook","microsoft","apple","netflix","instagram","twitter","bank"];
    const base = domain.split(".")[0];
    if (brands.some(b => base.includes(b)) && !SAFE_DOMAINS.has(domain)) { flags.push(`Brand impersonation detected: "${base}"`); score += 40; }
    if (content.includes("@")) { flags.push("@ symbol embedded in URL"); score += 30; }
    if (/[а-яА-ЯёЁ]/.test(hostname)) { flags.push("Cyrillic lookalike characters detected"); score += 45; }
    if (hostname.includes("--")) { flags.push("Double dash in domain"); score += 10; }
    const path = parsed.pathname + parsed.search;
    const phishKw = ["login","verify","secure","account","update","confirm","banking","password","signin","wallet","suspend"];
    const kws = phishKw.filter(k => path.toLowerCase().includes(k));
    if (kws.length >= 2) { flags.push(`Deceptive path keywords: ${kws.slice(0,3).join(", ")}`); score += kws.length * 5; }
    if (SAFE_DOMAINS.has(domain) && flags.length === 0) { goodSigns.push("Recognised as a trusted domain"); score = Math.max(0, score - 50); }
    if (parsed.protocol === "https:") goodSigns.push("Secured with HTTPS encryption");
    score = Math.min(100, score);
    const verdict = score >= 60 ? "DANGER" : score >= 25 ? "SUSPICIOUS" : "SAFE";
    return { verdict, riskScore: score, confidence: 72, heuristicFlags: flags, goodSigns, hostname, summary: verdict === "SAFE" ? "This address appears trustworthy upon initial inspection." : verdict === "SUSPICIOUS" ? "Certain irregularities give cause for concern." : "Multiple signs of treachery have been uncovered.", advice: verdict === "SAFE" ? "You may proceed, though eternal vigilance is advised." : "I counsel you not to proceed. Do not surrender your personal details.", category: "Preliminary Scan", isInstant: true };
  }
  if (mode === "email") {
    const text = content.toLowerCase();
    const flags = [], goodSigns = [];
    let score = 0;
    const urgencyWords = ["urgent","immediately","suspended","verify now","act now","expire","limited time","within 24","click here","confirm now"];
    const found = urgencyWords.filter(w => text.includes(w));
    if (found.length >= 2) { flags.push(`Language of urgency and fear: ${found.slice(0,2).join(", ")}`); score += 30; }
    if (/https?:\/\/[^\s]+/.test(text)) { const urls = text.match(/https?:\/\/[^\s]+/g) || []; const suspicious = urls.filter(u => /\.tk|\.xyz|\.ml|\.cf|\.ga|login|verify|secure/.test(u)); if (suspicious.length) { flags.push("Suspicious hyperlinks discovered"); score += 35; } }
    if (/password|credit card|social security|bank account|ssn|cvv/.test(text)) { flags.push("Solicitation of sensitive intelligence"); score += 40; }
    if (/(dear customer|dear user|dear account holder)/i.test(content)) { flags.push("Impersonal, generic salutation"); score += 15; }
    if (/prize|winner|won|lottery|reward|gift card/i.test(content)) { flags.push("Claims of prizes or rewards"); score += 25; }
    if (content.includes("unsubscribe") || content.includes("privacy policy")) goodSigns.push("Contains proper unsubscribe notice");
    if (/@[a-z0-9-]+\.[a-z]{2,}/i.test(content)) goodSigns.push("Contains identifiable email addresses");
    score = Math.min(100, score);
    const verdict = score >= 55 ? "DANGER" : score >= 20 ? "SUSPICIOUS" : "SAFE";
    return { verdict, riskScore: score, confidence: 65, heuristicFlags: flags, goodSigns, hostname: null, summary: verdict === "SAFE" ? "This correspondence appears to be of legitimate character." : verdict === "SUSPICIOUS" ? "This missive bears several troubling hallmarks." : "This letter reeks of deception and ill intent.", advice: verdict === "SAFE" ? "The correspondence appears genuine. Verify the sender nonetheless." : "Do not click any links nor surrender personal details.", category: "Preliminary Scan", isInstant: true };
  }
  if (mode === "sms") {
    const text = content.toLowerCase();
    const flags = [], goodSigns = [];
    let score = 0;
    if (/https?:\/\/[^\s]+/.test(text)) { const urls = text.match(/https?:\/\/[^\s]+/g) || []; if (urls.length) { flags.push("Contains a clickable hyperlink"); score += 20; } const sus = urls.filter(u => /\.tk|\.xyz|\.ml|\.cf|bit\.ly|tinyurl|short/.test(u)); if (sus.length) { flags.push("Shortened or suspicious link detected"); score += 30; } }
    if (/prize|winner|won|lottery|reward|gift|free|congratulations/i.test(content)) { flags.push("Claims of prizes or winnings"); score += 35; }
    if (/bank|account|suspended|verify|otp|password|credit|debit/i.test(content)) { flags.push("Financial or account urgency"); score += 30; }
    if (/delivery|package|parcel|dhl|fedex|ups|usps|shipment/i.test(content)) { const hasLink = /https?:\/\//.test(content); if (hasLink) { flags.push("Fraudulent delivery notice with link"); score += 35; } }
    if (/reply stop|txt stop|text stop/i.test(content)) goodSigns.push("Contains opt-out instruction");
    if (/\b\d{6}\b/.test(content)) goodSigns.push("Resembles a one-time passcode");
    score = Math.min(100, score);
    const verdict = score >= 55 ? "DANGER" : score >= 20 ? "SUSPICIOUS" : "SAFE";
    return { verdict, riskScore: score, confidence: 60, heuristicFlags: flags, goodSigns, hostname: null, summary: verdict === "SAFE" ? "This telegram appears to be of honest origin." : verdict === "SUSPICIOUS" ? "This telegram contains several suspicious elements." : "A classic smishing attack — do not be deceived!", advice: verdict === "SAFE" ? "Appears legitimate. Never share one-time codes with anyone." : "Never follow links received from unknown correspondents.", category: "Preliminary Scan", isInstant: true };
  }
  return null;
}

async function aiAnalyze(mode, content, heuristicFlags = []) {
  const prompts = {
    url: `You are a cybersecurity expert with a Victorian scholarly tone. Analyze this URL for phishing.\nURL: ${content}\nPre-scan flags: ${heuristicFlags.join(", ") || "none"}\nAnalyze: domain legitimacy, phishing indicators, brand impersonation, URL anomalies.`,
    email: `You are a cybersecurity expert with a Victorian scholarly tone. Analyze this email for phishing.\nEMAIL:\n${content}\nAnalyze: urgency tactics, suspicious links, sensitive info requests, brand impersonation, social engineering.`,
    sms: `You are a cybersecurity expert with a Victorian scholarly tone. Analyze this SMS for smishing.\nSMS:\n${content}\nAnalyze: suspicious links, urgency tactics, prize scams, bank/delivery impersonation.`,
  };
  const prompt = prompts[mode] + `\n\nRespond ONLY with valid JSON (no markdown, no backticks):\n{"verdict":"SAFE"|"SUSPICIOUS"|"DANGER","confidence":0-100,"riskScore":0-100,"summary":"one sentence in Victorian scholarly tone","threats":[],"goodSigns":[],"advice":"short Victorian-toned advice","category":"category name"}`;
  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "claude-sonnet-4-20250514", max_tokens: 600, messages: [{ role: "user", content: prompt }] })
  });
  if (!response.ok) throw new Error(`API error: ${response.status}`);
  const data = await response.json();
  const text = data.content.map(b => b.text || "").join("").trim();
  return JSON.parse(text.replace(/```json|```/g, "").trim());
}

const V = {
  SAFE:       { icon:"🌿", color:"#4a7c59", cardBg:"linear-gradient(160deg,#1a2e1f 0%,#0f1a12 100%)", border:"#2d5a35", label:"Deemed Safe", accent:"#7ec896", barColor:"#4a7c59", tagBg:"rgba(74,124,89,0.2)", tagColor:"#7ec896", glow:"rgba(74,124,89,0.3)" },
  SUSPICIOUS: { icon:"⚗️", color:"#c9a84c", cardBg:"linear-gradient(160deg,#2a2010 0%,#1a1408 100%)", border:"#6b5a1e", label:"Cause for Suspicion", accent:"#e8c96a", barColor:"#c9a84c", tagBg:"rgba(201,168,76,0.2)", tagColor:"#e8c96a", glow:"rgba(201,168,76,0.3)" },
  DANGER:     { icon:"☠️", color:"#c94a4a", cardBg:"linear-gradient(160deg,#2a0f0f 0%,#1a0808 100%)", border:"#6b1e1e", label:"Grave Danger Detected", accent:"#e87a7a", barColor:"#c94a4a", tagBg:"rgba(201,74,74,0.2)", tagColor:"#e87a7a", glow:"rgba(201,74,74,0.3)" },
};

const TABS = [
  { id:"url",   label:"URL Scroll",   icon:"📜", placeholder:"https://address-to-examine.com", inputLabel:"Present the URL for examination", btn:"Examine Address", multi:false },
  { id:"email", label:"Correspondence", icon:"✉️", placeholder:"Paste the full contents of the correspondence herein...", inputLabel:"Present the correspondence for scrutiny", btn:"Scrutinise Letter", multi:true },
  { id:"sms",   label:"Telegram",     icon:"📡", placeholder:"Paste the telegram message herein...", inputLabel:"Present the telegram for inspection", btn:"Inspect Telegram", multi:true },
];

function OrnamentalDivider() {
  return (
    <div style={{display:"flex",alignItems:"center",gap:12,margin:"16px 0",opacity:0.5}}>
      <div style={{flex:1,height:1,background:"linear-gradient(90deg,transparent,#8b7355)"}}/>
      <span style={{color:"#8b7355",fontSize:14,letterSpacing:4}}>✦ ✦ ✦</span>
      <div style={{flex:1,height:1,background:"linear-gradient(90deg,#8b7355,transparent)"}}/>
    </div>
  );
}

function Tag({ children, bg, color }) {
  return (
    <span style={{background:bg,color,borderRadius:3,padding:"3px 10px",fontSize:11,fontFamily:"'IM Fell English',serif",fontWeight:400,display:"inline-block",margin:"2px 3px",border:`1px solid ${color}44`,letterSpacing:"0.05em"}}>
      {children}
    </span>
  );
}

export default function App() {
  const [tab, setTab] = useState("url");
  const [inputs, setInputs] = useState({ url:"", email:"", sms:"" });
  const [results, setResults] = useState({ url:null, email:null, sms:null });
  const [aiLoading, setAiLoading] = useState(false);
  const [errors, setErrors] = useState({ url:"", email:"", sms:"" });
  const [showConfirm, setShowConfirm] = useState(false);
  const [showUrlPicker, setShowUrlPicker] = useState(false);
  const [confirmTarget, setConfirmTarget] = useState(null);
  const [shake, setShake] = useState(false);
  const [musicPlaying, setMusicPlaying] = useState(false);
  const audioRef = useRef(null);

  // Free royalty-free tracks from Pixabay CDN matching each mood
  const MUSIC = {
    SAFE:       "https://cdn.pixabay.com/download/audio/2022/03/15/audio_8a4f79d8d8.mp3", // cheerful acoustic
    SUSPICIOUS: "https://cdn.pixabay.com/download/audio/2022/10/25/audio_946e3fd97e.mp3", // tense suspense
    DANGER:     "https://cdn.pixabay.com/download/audio/2022/03/24/audio_3df8fd7e72.mp3", // dark dramatic
  };

  const lastVerdict = useRef(null);
  useEffect(() => {
    const verdict = result?.verdict;
    if (!verdict || verdict === lastVerdict.current) return;
    lastVerdict.current = verdict;
    const src = MUSIC[verdict];
    if (!src || !audioRef.current) return;
    audioRef.current.pause();
    audioRef.current.src = src;
    audioRef.current.volume = 0.35;
    audioRef.current.loop = true;
    audioRef.current.play().then(() => setMusicPlaying(true)).catch(() => {});
  });

  const toggleMusic = () => {
    if (!audioRef.current) return;
    if (musicPlaying) { audioRef.current.pause(); setMusicPlaying(false); }
    else { audioRef.current.play(); setMusicPlaying(true); }
  };

  const input = inputs[tab];
  const result = results[tab];
  const error = errors[tab];
  const cfg = result ? V[result.verdict] || V.SUSPICIOUS : null;

  const setInput = v => setInputs(p => ({ ...p, [tab]: v }));
  const setError = v => setErrors(p => ({ ...p, [tab]: v }));
  const setResult = v => setResults(p => ({ ...p, [tab]: v }));

  const analyze = async () => {
    setError("");
    let valid = false, content = input, hFlags = [], hostname = "";
    if (tab === "url") {
      const v = validateURL(input);
      if (!v.valid) { setError(v.reason); setShake(true); setTimeout(() => setShake(false), 500); return; }
      content = v.normalizedUrl; hostname = v.hostname; valid = true;
    } else if (tab === "email") {
      const v = validateEmail(input);
      if (!v.valid) { setError(v.reason); setShake(true); setTimeout(() => setShake(false), 500); return; }
      valid = true;
    } else {
      const v = validateSMS(input);
      if (!v.valid) { setError(v.reason); setShake(true); setTimeout(() => setShake(false), 500); return; }
      valid = true;
    }
    if (!valid) return;
    const instant = instantScan(tab, content);
    if (instant) setResult(instant);
    setAiLoading(true);
    try {
      const ai = await aiAnalyze(tab, content, instant?.heuristicFlags || []);
      setResult({ ...ai, hostname: hostname || null, heuristicFlags: instant?.heuristicFlags || [], isInstant: false });
    } catch (e) {
      if (instant) setResult({ ...instant, aiError: true });
    } finally {
      setAiLoading(false);
    }
  };

  const extractURLs = (text) => [...new Set((text.match(/https?:\/\/[^\s"'<>]+/g) || []))];
  const doOpen = (url) => { window.open(url, "_blank", "noopener,noreferrer"); };
  const handleOpen = (overrideTarget) => {
    let target = overrideTarget;
    if (!target) {
      if (tab === "url") { target = input.startsWith("http") ? input : "https://" + input; }
      else {
        const urls = extractURLs(input);
        if (urls.length === 1) target = urls[0];
        else if (urls.length > 1) { setShowUrlPicker(true); return; }
        else return;
      }
    }
    if (result?.verdict === "SAFE") { doOpen(target); }
    else { setConfirmTarget({ value: target }); setShowConfirm(true); }
  };

  const urlsInContent = (tab === "email" || tab === "sms") ? extractURLs(input) : [];
  const canOpen = tab === "url" ? input.trim().length > 3 : urlsInContent.length > 0;
  const tabCfg = TABS.find(t => t.id === tab);

  return (
    <div style={{minHeight:"100vh",background:"#0a0804",fontFamily:"'IM Fell English',serif",display:"flex",flexDirection:"column",alignItems:"center",padding:"40px 16px 80px",position:"relative",overflow:"hidden"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IM+Fell+English:ital@0;1&family=Cinzel:wght@400;600;700;900&family=Crimson+Text:ital,wght@0,400;0,600;1,400&display=swap');
        *{box-sizing:border-box}

        /* Parchment texture overlay */
        body { background: #0a0804; }

        @keyframes flicker { 0%,100%{opacity:1} 92%{opacity:.97} 94%{opacity:.88} 96%{opacity:.99} }
        @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-8px)} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
        @keyframes shake { 0%,100%{transform:translateX(0)} 20%,60%{transform:translateX(-5px)} 40%,80%{transform:translateX(5px)} }
        @keyframes popIn { 0%{transform:scale(0.9);opacity:0} 100%{transform:scale(1);opacity:1} }
        @keyframes scanGlow { 0%,100%{box-shadow:0 0 10px rgba(139,115,85,0.3)} 50%{box-shadow:0 0 25px rgba(139,115,85,0.6)} }
        @keyframes spin { to{transform:rotate(360deg)} }
        @keyframes candleFlicker { 0%,100%{opacity:0.6;transform:scale(1)} 50%{opacity:0.9;transform:scale(1.05)} }
        @keyframes borderGlow { 0%,100%{border-color:rgba(139,115,85,0.4)} 50%{border-color:rgba(139,115,85,0.8)} }

        .btn { transition:all .2s; cursor:pointer; border:none; }
        .btn:hover { transform:translateY(-2px) !important; filter:brightness(1.1); }
        .btn:active { transform:translateY(1px) !important; }
        .tab-btn { transition:all .2s; cursor:pointer; border:none; }
        .inp:focus { outline:none !important; border-color:rgba(139,115,85,0.8) !important; box-shadow:0 0 0 3px rgba(139,115,85,0.15), inset 0 0 20px rgba(0,0,0,0.3) !important; }
        .inp::placeholder { color: rgba(139,115,85,0.4); font-style:italic; }

        /* Ornate corner decorations */
        .ornate-card { position:relative; }
        .ornate-card::before, .ornate-card::after {
          content: '❧';
          position: absolute;
          font-size: 20px;
          color: rgba(139,115,85,0.5);
          pointer-events: none;
        }
        .ornate-card::before { top: 10px; left: 14px; }
        .ornate-card::after { bottom: 10px; right: 14px; transform: rotate(180deg); }

        /* Noise texture overlay */
        .noise::after {
          content:'';
          position:absolute;
          inset:0;
          background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.04'/%3E%3C/svg%3E");
          pointer-events:none;
          border-radius:inherit;
          opacity:0.4;
        }
      `}</style>

      {/* Background atmospheric elements */}
      <div style={{position:"fixed",inset:0,pointerEvents:"none",zIndex:0}}>
        {/* Vignette */}
        <div style={{position:"absolute",inset:0,background:"radial-gradient(ellipse at center, transparent 30%, rgba(0,0,0,0.85) 100%)"}}/>
        {/* Subtle parchment lines */}
        <div style={{position:"absolute",inset:0,backgroundImage:"repeating-linear-gradient(0deg,transparent,transparent 28px,rgba(139,115,85,0.03) 28px,rgba(139,115,85,0.03) 29px)",opacity:0.5}}/>
        {/* Corner flourishes */}
        {[{t:0,l:0},{t:0,r:0},{b:0,l:0},{b:0,r:0}].map((pos,i)=>(
          <div key={i} style={{position:"absolute",...(pos.t!==undefined?{top:20}:{bottom:20}),...(pos.l!==undefined?{left:20}:{right:20}),width:80,height:80,border:"1px solid rgba(139,115,85,0.2)",transform:`rotate(${i*90}deg)`,borderRadius:"2px 0 0 0",opacity:0.6}}/>
        ))}
        {/* Floating particles */}
        {Array.from({length:12}).map((_,i)=>(
          <div key={i} style={{position:"absolute",left:`${(i*17+7)%95}%`,top:`${(i*23+11)%90}%`,width:2,height:2,background:"rgba(139,115,85,0.4)",borderRadius:"50%",animation:`float ${3+i*0.4}s ease-in-out infinite`,animationDelay:`${i*0.5}s`}}/>
        ))}
      </div>

      {/* Hidden audio player */}
      <audio ref={audioRef} style={{display:"none"}}/>

      {/* Music toggle button — only show when result exists */}
      {result && cfg && (
        <button onClick={toggleMusic} className="btn" style={{position:"fixed",bottom:24,right:24,zIndex:100,background:"linear-gradient(135deg,#2a1f0e,#3d2d15)",border:`1px solid ${cfg.border}`,borderRadius:"50%",width:52,height:52,display:"flex",alignItems:"center",justifyContent:"center",fontSize:22,boxShadow:`0 4px 20px rgba(0,0,0,0.6), 0 0 20px ${cfg.glow}`,cursor:"pointer"}} title={musicPlaying ? "Pause music" : "Play music"}>
          {musicPlaying ? "⏸" : "▶️"}
        </button>
      )}

      <div style={{position:"relative",zIndex:2,width:"100%",maxWidth:580,animation:"fadeUp .8s ease"}}>

        {/* HEADER */}
        <div style={{textAlign:"center",marginBottom:36}}>
          {/* Top ornament */}
          <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:16,marginBottom:20,opacity:0.6}}>
            <div style={{height:1,width:60,background:"linear-gradient(90deg,transparent,#8b7355)"}}/>
            <span style={{color:"#8b7355",fontSize:11,letterSpacing:6,fontFamily:"'Cinzel',serif",textTransform:"uppercase"}}>E.S.T 2026</span>
            <div style={{height:1,width:60,background:"linear-gradient(90deg,#8b7355,transparent)"}}/>
          </div>

          {/* Main icon */}
          <div style={{lineHeight:1,animation:"float 4s ease-in-out infinite,candleFlicker 3s ease-in-out infinite",display:"inline-block",marginBottom:16,filter:"drop-shadow(0 0 25px rgba(180,140,60,0.7))"}}>
            <svg width="80" height="64" viewBox="0 0 160 128" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <radialGradient id="wing1" cx="35%" cy="40%" r="60%">
                  <stop offset="0%" stopColor="#f0c040"/>
                  <stop offset="40%" stopColor="#c8902a"/>
                  <stop offset="75%" stopColor="#7a4e10"/>
                  <stop offset="100%" stopColor="#1a0f00"/>
                </radialGradient>
                <radialGradient id="wing2" cx="65%" cy="40%" r="60%">
                  <stop offset="0%" stopColor="#f0c040"/>
                  <stop offset="40%" stopColor="#c8902a"/>
                  <stop offset="75%" stopColor="#7a4e10"/>
                  <stop offset="100%" stopColor="#1a0f00"/>
                </radialGradient>
                <radialGradient id="wing3" cx="30%" cy="35%" r="65%">
                  <stop offset="0%" stopColor="#d4a832"/>
                  <stop offset="50%" stopColor="#8b5e18"/>
                  <stop offset="100%" stopColor="#1a0f00"/>
                </radialGradient>
                <radialGradient id="wing4" cx="70%" cy="35%" r="65%">
                  <stop offset="0%" stopColor="#d4a832"/>
                  <stop offset="50%" stopColor="#8b5e18"/>
                  <stop offset="100%" stopColor="#1a0f00"/>
                </radialGradient>
              </defs>
              {/* Upper wings */}
              <path d="M80 58 C72 44, 52 20, 28 14 C12 10, 4 22, 8 36 C12 50, 30 58, 50 62 C62 65, 74 63, 80 58Z" fill="url(#wing1)" stroke="#0a0600" strokeWidth="1.2"/>
              <path d="M80 58 C88 44, 108 20, 132 14 C148 10, 156 22, 152 36 C148 50, 130 58, 110 62 C98 65, 86 63, 80 58Z" fill="url(#wing2)" stroke="#0a0600" strokeWidth="1.2"/>
              {/* Lower wings */}
              <path d="M80 62 C70 66, 44 68, 26 80 C14 88, 16 102, 28 106 C42 110, 62 98, 72 84 C77 76, 80 68, 80 62Z" fill="url(#wing3)" stroke="#0a0600" strokeWidth="1.2"/>
              <path d="M80 62 C90 66, 116 68, 134 80 C146 88, 144 102, 132 106 C118 110, 98 98, 88 84 C83 76, 80 68, 80 62Z" fill="url(#wing4)" stroke="#0a0600" strokeWidth="1.2"/>
              {/* Venation upper left */}
              <path d="M80 58 C72 50, 55 32, 36 22" stroke="#0a0600" strokeWidth="0.8" fill="none" opacity="0.7"/>
              <path d="M80 58 C68 52, 48 42, 30 42" stroke="#0a0600" strokeWidth="0.6" fill="none" opacity="0.6"/>
              <path d="M80 58 C70 56, 52 54, 36 56" stroke="#0a0600" strokeWidth="0.5" fill="none" opacity="0.5"/>
              <path d="M55 32 C50 38, 42 46, 36 56" stroke="#0a0600" strokeWidth="0.5" fill="none" opacity="0.5"/>
              <path d="M36 22 C34 30, 32 40, 30 42" stroke="#0a0600" strokeWidth="0.4" fill="none" opacity="0.45"/>
              {/* Venation upper right */}
              <path d="M80 58 C88 50, 105 32, 124 22" stroke="#0a0600" strokeWidth="0.8" fill="none" opacity="0.7"/>
              <path d="M80 58 C92 52, 112 42, 130 42" stroke="#0a0600" strokeWidth="0.6" fill="none" opacity="0.6"/>
              <path d="M80 58 C90 56, 108 54, 124 56" stroke="#0a0600" strokeWidth="0.5" fill="none" opacity="0.5"/>
              <path d="M105 32 C110 38, 118 46, 124 56" stroke="#0a0600" strokeWidth="0.5" fill="none" opacity="0.5"/>
              <path d="M124 22 C126 30, 128 40, 130 42" stroke="#0a0600" strokeWidth="0.4" fill="none" opacity="0.45"/>
              {/* Venation lower left */}
              <path d="M80 62 C72 72, 54 82, 36 90" stroke="#0a0600" strokeWidth="0.6" fill="none" opacity="0.55"/>
              <path d="M80 62 C68 76, 50 88, 38 98" stroke="#0a0600" strokeWidth="0.5" fill="none" opacity="0.5"/>
              <path d="M54 82 C50 88, 44 94, 38 98" stroke="#0a0600" strokeWidth="0.4" fill="none" opacity="0.4"/>
              {/* Venation lower right */}
              <path d="M80 62 C88 72, 106 82, 124 90" stroke="#0a0600" strokeWidth="0.6" fill="none" opacity="0.55"/>
              <path d="M80 62 C92 76, 110 88, 122 98" stroke="#0a0600" strokeWidth="0.5" fill="none" opacity="0.5"/>
              <path d="M106 82 C110 88, 116 94, 122 98" stroke="#0a0600" strokeWidth="0.4" fill="none" opacity="0.4"/>
              {/* Black border markings */}
              <path d="M80 58 C72 44, 52 20, 28 14 C12 10, 4 22, 8 36 C12 50, 30 58, 50 62 C62 65, 74 63, 80 58Z" fill="none" stroke="#0f0900" strokeWidth="5" opacity="0.5"/>
              <path d="M80 58 C88 44, 108 20, 132 14 C148 10, 156 22, 152 36 C148 50, 130 58, 110 62 C98 65, 86 63, 80 58Z" fill="none" stroke="#0f0900" strokeWidth="5" opacity="0.5"/>
              {/* Gold shimmer spots */}
              <ellipse cx="46" cy="38" rx="10" ry="7" fill="#f5d060" opacity="0.35" transform="rotate(-20 46 38)"/>
              <ellipse cx="114" cy="38" rx="10" ry="7" fill="#f5d060" opacity="0.35" transform="rotate(20 114 38)"/>
              <ellipse cx="42" cy="86" rx="7" ry="5" fill="#e8c040" opacity="0.3" transform="rotate(-10 42 86)"/>
              <ellipse cx="118" cy="86" rx="7" ry="5" fill="#e8c040" opacity="0.3" transform="rotate(10 118 86)"/>
              {/* Body */}
              <ellipse cx="80" cy="64" rx="4" ry="32" fill="#1a0f00" stroke="#5a3e10" strokeWidth="1"/>
              <ellipse cx="80" cy="64" rx="2.5" ry="30" fill="#2a1a05"/>
              {[52,58,64,70,76,82,88].map((y,i) => (
                <ellipse key={i} cx="80" cy={y} rx="3.5" ry="2.5" fill="none" stroke="#5a3e10" strokeWidth="0.5" opacity="0.6"/>
              ))}
              {/* Head */}
              <circle cx="80" cy="44" r="5" fill="#1a0f00" stroke="#7a5a20" strokeWidth="0.8"/>
              <circle cx="80" cy="44" r="3" fill="#2a1a05"/>
              {/* Eyes */}
              <circle cx="77.5" cy="43" r="1.2" fill="#c8902a"/>
              <circle cx="82.5" cy="43" r="1.2" fill="#c8902a"/>
              <circle cx="77.5" cy="43" r="0.5" fill="#f0c040"/>
              <circle cx="82.5" cy="43" r="0.5" fill="#f0c040"/>
              {/* Antennae */}
              <path d="M78 40 C74 32, 68 24, 64 18" stroke="#3a2808" strokeWidth="0.9" fill="none"/>
              <path d="M82 40 C86 32, 92 24, 96 18" stroke="#3a2808" strokeWidth="0.9" fill="none"/>
              <circle cx="64" cy="17" r="2" fill="#c8902a" stroke="#f0c040" strokeWidth="0.5"/>
              <circle cx="96" cy="17" r="2" fill="#c8902a" stroke="#f0c040" strokeWidth="0.5"/>
            </svg>
          </div>

          <h1 style={{margin:"0 0 8px",fontFamily:"'Cinzel',serif",fontWeight:900,fontSize:"clamp(22px,5vw,38px)",color:"#d4b896",letterSpacing:"0.08em",textTransform:"uppercase",textShadow:"0 0 40px rgba(212,184,150,0.3)"}}>
            The Phishing Detector
          </h1>
          <p style={{fontFamily:"'IM Fell English',serif",fontStyle:"italic",color:"rgba(139,115,85,0.8)",fontSize:14,margin:"0 0 16px",letterSpacing:"0.05em"}}>
            A Scholarly Instrument for the Detection of Digital Deception
          </p>

          <div style={{display:"inline-flex",alignItems:"center",gap:8,background:"rgba(139,115,85,0.08)",border:"1px solid rgba(139,115,85,0.3)",borderRadius:2,padding:"6px 18px"}}>
            <span style={{fontSize:11}}>⚜️</span>
            <span style={{fontFamily:"'Cinzel',serif",fontWeight:600,fontSize:10,color:"rgba(139,115,85,0.9)",letterSpacing:"0.15em",textTransform:"uppercase"}}>Powered by Artificial Intelligence</span>
            <span style={{fontSize:11}}>⚜️</span>
          </div>
        </div>

        {/* TABS */}
        <div style={{display:"flex",gap:0,marginBottom:20,border:"1px solid rgba(139,115,85,0.3)",borderRadius:3,overflow:"hidden",background:"rgba(0,0,0,0.4)"}}>
          {TABS.map((t,i)=>(
            <button key={t.id} className="tab-btn" onClick={()=>setTab(t.id)} style={{flex:1,padding:"12px 8px",fontFamily:"'Cinzel',serif",fontWeight:tab===t.id?600:400,fontSize:11,background:tab===t.id?"rgba(139,115,85,0.2)":"transparent",color:tab===t.id?"#d4b896":"rgba(139,115,85,0.6)",borderLeft:i>0?"1px solid rgba(139,115,85,0.2)":"none",letterSpacing:"0.08em",textTransform:"uppercase",transition:"all .2s",textShadow:tab===t.id?"0 0 20px rgba(212,184,150,0.4)":"none"}}>
              <div style={{fontSize:16,marginBottom:3}}>{t.icon}</div>
              {t.label}
            </button>
          ))}
        </div>

        {/* INPUT CARD */}
        <div className="ornate-card noise" style={{background:"linear-gradient(160deg,#120f08 0%,#0a0804 100%)",borderRadius:4,padding:"28px 28px 24px",boxShadow:"0 20px 60px rgba(0,0,0,0.8), inset 0 1px 0 rgba(139,115,85,0.2)",border:"1px solid rgba(139,115,85,0.3)",marginBottom:20,position:"relative",overflow:"hidden",animation:shake?"shake .5s":"none"}}>

          {/* Inner glow */}
          <div style={{position:"absolute",top:0,left:0,right:0,height:1,background:"linear-gradient(90deg,transparent,rgba(139,115,85,0.4),transparent)"}}/>

          <label style={{display:"block",fontFamily:"'Cinzel',serif",fontWeight:600,fontSize:10,color:"rgba(139,115,85,0.8)",marginBottom:14,letterSpacing:"0.2em",textTransform:"uppercase"}}>
            ✦ {tabCfg.inputLabel}
          </label>

          {tabCfg.multi ? (
            <textarea className="inp" value={input} onChange={e=>{setInput(e.target.value);setError("");}} placeholder={tabCfg.placeholder} rows={5}
              style={{width:"100%",background:"rgba(0,0,0,0.5)",border:"1px solid rgba(139,115,85,0.25)",borderRadius:3,color:"#c8b89a",padding:"12px 16px",fontSize:13,fontFamily:"'Crimson Text',serif",resize:"vertical",lineHeight:1.7,transition:"all .3s",letterSpacing:"0.02em"}}/>
          ) : (
            <input className="inp" value={input} onChange={e=>{setInput(e.target.value);setError("");}} onKeyDown={e=>e.key==="Enter"&&analyze()} placeholder={tabCfg.placeholder}
              style={{width:"100%",background:"rgba(0,0,0,0.5)",border:"1px solid rgba(139,115,85,0.25)",borderRadius:3,color:"#c8b89a",padding:"12px 16px",fontSize:13,fontFamily:"'Crimson Text',serif",transition:"all .3s",letterSpacing:"0.02em"}}/>
          )}

          <OrnamentalDivider />

          <button className="btn" onClick={analyze} disabled={aiLoading && !result}
            style={{width:"100%",background:"linear-gradient(135deg,#2a1f0e 0%,#3d2d15 50%,#2a1f0e 100%)",color:"#d4b896",borderRadius:3,padding:"14px",fontFamily:"'Cinzel',serif",fontWeight:600,fontSize:13,border:"1px solid rgba(139,115,85,0.5)",letterSpacing:"0.15em",textTransform:"uppercase",boxShadow:"0 4px 20px rgba(0,0,0,0.5), inset 0 1px 0 rgba(139,115,85,0.2)",textShadow:"0 0 20px rgba(212,184,150,0.4)"}}>
            {aiLoading && !result ? (
              <span style={{display:"flex",alignItems:"center",justifyContent:"center",gap:10}}>
                <div style={{width:12,height:12,border:"1.5px solid rgba(139,115,85,0.4)",borderTop:"1.5px solid #d4b896",borderRadius:"50%",animation:"spin .8s linear infinite"}}/>
                Consulting the Oracle...
              </span>
            ) : `⚜ ${tabCfg.btn} ⚜`}
          </button>

          {error && (
            <div style={{marginTop:14,background:"rgba(139,40,40,0.15)",border:"1px solid rgba(139,40,40,0.4)",borderRadius:3,padding:"10px 16px",fontFamily:"'IM Fell English',serif",fontStyle:"italic",fontSize:13,color:"#c87878",letterSpacing:"0.02em"}}>
              ✗ {error}
            </div>
          )}
        </div>

        {/* RESULT CARD */}
        {result && cfg && (
          <div className="noise" style={{background:cfg.cardBg,borderRadius:4,padding:"28px",boxShadow:`0 20px 60px rgba(0,0,0,0.8), 0 0 40px ${cfg.glow}, inset 0 1px 0 rgba(255,255,255,0.05)`,border:`1px solid ${cfg.border}`,animation:"popIn .4s ease",position:"relative",overflow:"hidden"}}>

            <div style={{position:"absolute",top:0,left:0,right:0,height:1,background:`linear-gradient(90deg,transparent,${cfg.color},transparent)`,opacity:0.6}}/>

            {/* Status badges */}
            <div style={{position:"absolute",top:16,right:16}}>
              {aiLoading && (
                <div style={{display:"flex",alignItems:"center",gap:6,background:"rgba(0,0,0,0.5)",border:"1px solid rgba(139,115,85,0.3)",borderRadius:2,padding:"4px 12px"}}>
                  <div style={{width:8,height:8,border:"1.5px solid rgba(139,115,85,0.4)",borderTop:`1.5px solid #d4b896`,borderRadius:"50%",animation:"spin .8s linear infinite"}}/>
                  <span style={{fontFamily:"'Cinzel',serif",fontSize:9,color:"rgba(139,115,85,0.8)",letterSpacing:"0.1em"}}>ORACLE CONSULTING</span>
                </div>
              )}
              {result.isInstant && !aiLoading && (
                <div style={{background:"rgba(0,0,0,0.5)",border:"1px solid rgba(139,115,85,0.25)",borderRadius:2,padding:"4px 12px"}}>
                  <span style={{fontFamily:"'Cinzel',serif",fontSize:9,color:"rgba(139,115,85,0.6)",letterSpacing:"0.1em"}}>PRELIMINARY</span>
                </div>
              )}
              {!result.isInstant && !aiLoading && (
                <div style={{background:"rgba(0,0,0,0.5)",border:`1px solid ${cfg.border}`,borderRadius:2,padding:"4px 12px",animation:"fadeUp .4s ease"}}>
                  <span style={{fontFamily:"'Cinzel',serif",fontSize:9,color:cfg.accent,letterSpacing:"0.1em"}}>✦ AI VERIFIED</span>
                </div>
              )}
            </div>

            {/* Verdict header */}
            <div style={{textAlign:"center",marginBottom:24}}>
              <div style={{fontSize:56,lineHeight:1.1,marginBottom:10,filter:`drop-shadow(0 0 20px ${cfg.color})`}}>{cfg.icon}</div>
              <div style={{fontFamily:"'Cinzel',serif",fontWeight:700,fontSize:20,color:cfg.accent,letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:4,textShadow:`0 0 30px ${cfg.glow}`}}>
                {cfg.label}
              </div>
              {result.category && result.category !== "Preliminary Scan" && (
                <div style={{marginTop:8}}>
                  <Tag bg={cfg.tagBg} color={cfg.tagColor}>📂 {result.category}</Tag>
                </div>
              )}
            </div>

            <OrnamentalDivider />

            {/* Scores */}
            <div style={{background:"rgba(0,0,0,0.4)",borderRadius:3,padding:"16px 20px",marginBottom:18,border:"1px solid rgba(139,115,85,0.15)"}}>
              <div style={{display:"flex",justifyContent:"space-around",alignItems:"center",marginBottom:16}}>
                <div style={{textAlign:"center"}}>
                  <div style={{fontFamily:"'Cinzel',serif",fontSize:9,color:"rgba(139,115,85,0.6)",textTransform:"uppercase",letterSpacing:"0.15em",marginBottom:4}}>Peril Score</div>
                  <div style={{fontFamily:"'Cinzel',serif",fontWeight:700,fontSize:36,color:cfg.accent,lineHeight:1,textShadow:`0 0 20px ${cfg.glow}`}}>{result.riskScore}<span style={{fontSize:14,color:"rgba(139,115,85,0.4)"}}>/100</span></div>
                </div>
                <div style={{width:1,height:40,background:"rgba(139,115,85,0.2)"}}/>
                <div style={{textAlign:"center"}}>
                  <div style={{fontFamily:"'Cinzel',serif",fontSize:9,color:"rgba(139,115,85,0.6)",textTransform:"uppercase",letterSpacing:"0.15em",marginBottom:4}}>Certainty</div>
                  <div style={{fontFamily:"'Cinzel',serif",fontWeight:700,fontSize:36,color:cfg.color,lineHeight:1,textShadow:`0 0 20px ${cfg.glow}`}}>{result.confidence}<span style={{fontSize:14,color:"rgba(139,115,85,0.4)"}}>%</span></div>
                </div>
              </div>
              {/* Progress bar */}
              <div style={{height:6,background:"rgba(0,0,0,0.5)",borderRadius:99,overflow:"hidden",border:"1px solid rgba(139,115,85,0.1)"}}>
                <div style={{height:"100%",width:`${result.riskScore}%`,background:`linear-gradient(90deg,rgba(139,115,85,0.4),${cfg.barColor})`,borderRadius:99,transition:"width 1.2s ease",boxShadow:`0 0 10px ${cfg.color}`}}/>
              </div>
            </div>

            {/* Summary */}
            {result.summary && (
              <div style={{background:"rgba(0,0,0,0.3)",borderRadius:3,padding:"14px 18px",marginBottom:16,border:"1px solid rgba(139,115,85,0.15)",display:"flex",gap:12,alignItems:"flex-start"}}>
                <span style={{fontSize:18,flexShrink:0,opacity:0.8}}>🔍</span>
                <div>
                  <div style={{fontFamily:"'Cinzel',serif",fontSize:9,color:"rgba(139,115,85,0.6)",textTransform:"uppercase",letterSpacing:"0.15em",marginBottom:6}}>The Oracle's Assessment</div>
                  <div style={{fontFamily:"'IM Fell English',serif",fontStyle:"italic",fontSize:14,color:"#c8b89a",lineHeight:1.7}}>{result.summary}</div>
                </div>
              </div>
            )}

            {/* Hostname */}
            {result.hostname && (
              <div style={{background:"rgba(0,0,0,0.3)",borderRadius:3,padding:"10px 16px",marginBottom:14,border:"1px solid rgba(139,115,85,0.15)",display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}>
                <span style={{fontSize:13,opacity:0.6}}>🌐</span>
                <span style={{fontFamily:"'Crimson Text',serif",color:cfg.accent,fontSize:13,wordBreak:"break-all",letterSpacing:"0.02em"}}>{result.hostname}</span>
              </div>
            )}

            {/* Threats */}
            {result.threats?.length > 0 && (
              <div style={{marginBottom:14}}>
                <div style={{fontFamily:"'Cinzel',serif",fontSize:9,color:"#e87a7a",textTransform:"uppercase",letterSpacing:"0.15em",marginBottom:10}}>⚠ Treacheries Uncovered</div>
                {result.threats.map((t,i)=>(
                  <div key={i} style={{background:"rgba(139,40,40,0.1)",borderRadius:3,padding:"8px 14px",marginBottom:6,display:"flex",gap:10,alignItems:"flex-start",border:"1px solid rgba(139,40,40,0.25)",fontFamily:"'Crimson Text',serif",fontSize:13,color:"#c87878",lineHeight:1.5,animation:`fadeUp .3s ${i*.06}s both`}}>
                    <span style={{flexShrink:0,opacity:0.7}}>✗</span>{t}
                  </div>
                ))}
              </div>
            )}

            {/* Heuristic flags */}
            {result.heuristicFlags?.length > 0 && (
              <div style={{marginBottom:14}}>
                <div style={{fontFamily:"'Cinzel',serif",fontSize:9,color:"rgba(201,168,76,0.8)",textTransform:"uppercase",letterSpacing:"0.15em",marginBottom:8}}>⚗ Findings of the Preliminary Scan</div>
                <div style={{display:"flex",flexWrap:"wrap",gap:4}}>
                  {result.heuristicFlags.map((f,i)=><Tag key={i} bg="rgba(201,168,76,0.1)" color="rgba(201,168,76,0.8)">⚑ {f}</Tag>)}
                </div>
              </div>
            )}

            {/* Good signs */}
            {result.goodSigns?.length > 0 && (
              <div style={{marginBottom:16}}>
                <div style={{fontFamily:"'Cinzel',serif",fontSize:9,color:"rgba(74,124,89,0.8)",textTransform:"uppercase",letterSpacing:"0.15em",marginBottom:10}}>✦ Marks of Trustworthiness</div>
                {result.goodSigns.map((g,i)=>(
                  <div key={i} style={{background:"rgba(74,124,89,0.1)",borderRadius:3,padding:"8px 14px",marginBottom:6,display:"flex",gap:10,alignItems:"flex-start",border:"1px solid rgba(74,124,89,0.2)",fontFamily:"'Crimson Text',serif",fontSize:13,color:"#7ec896",lineHeight:1.5,animation:`fadeUp .3s ${i*.06}s both`}}>
                    <span style={{flexShrink:0,opacity:0.7}}>✓</span>{g}
                  </div>
                ))}
              </div>
            )}

            {/* Advice */}
            {result.advice && (
              <div style={{background:"rgba(0,0,0,0.35)",borderRadius:3,padding:"12px 16px",marginBottom:16,border:`1px solid ${cfg.border}`,display:"flex",gap:10,alignItems:"flex-start"}}>
                <span style={{fontSize:15,flexShrink:0,opacity:0.7}}>📜</span>
                <div style={{fontFamily:"'IM Fell English',serif",fontStyle:"italic",fontSize:13,color:"rgba(200,184,154,0.8)",lineHeight:1.7}}>"{result.advice}"</div>
              </div>
            )}

            <OrnamentalDivider />

            {/* Open button */}
            {canOpen && (
              <button className="btn" onClick={()=>handleOpen()}
                style={{width:"100%",background:result.verdict==="SAFE"?"linear-gradient(135deg,#1a2e1f,#2d4a35)":"linear-gradient(135deg,#2a1508,#3d2210)",color:result.verdict==="SAFE"?"#7ec896":"#e8a050",borderRadius:3,padding:"14px",fontFamily:"'Cinzel',serif",fontWeight:600,fontSize:12,border:`1px solid ${cfg.border}`,letterSpacing:"0.15em",textTransform:"uppercase",boxShadow:`0 4px 20px rgba(0,0,0,0.5), 0 0 20px ${cfg.glow}`}}>
                {result.verdict==="SAFE"
                  ? `⚜ Proceed to ${tab==="url"?"the Address":tab==="email"?"the Link":"the Link"} ⚜`
                  : `⚠ Proceed at Your Own Peril ⚠`}
              </button>
            )}
          </div>
        )}

        {/* Footer */}
        <div style={{textAlign:"center",marginTop:28}}>
          <OrnamentalDivider />
          <p style={{fontFamily:"'IM Fell English',serif",fontStyle:"italic",fontSize:11,color:"rgba(139,115,85,0.4)",letterSpacing:"0.05em"}}>
            Crafted with devotion · Powered by the Claude Oracle · Results are of an informational nature only
          </p>
        </div>
      </div>

      {/* URL PICKER MODAL */}
      {showUrlPicker && (
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.85)",backdropFilter:"blur(8px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:999,padding:20}}>
          <div style={{background:"linear-gradient(160deg,#120f08,#0a0804)",borderRadius:4,padding:"32px 28px",maxWidth:460,width:"100%",boxShadow:"0 30px 80px rgba(0,0,0,0.9), 0 0 40px rgba(139,115,85,0.15)",border:"1px solid rgba(139,115,85,0.35)",animation:"popIn .35s ease"}}>
            <div style={{textAlign:"center",marginBottom:20}}>
              <div style={{fontSize:36,marginBottom:10,opacity:0.8}}>🔗</div>
              <h3 style={{fontFamily:"'Cinzel',serif",fontWeight:700,color:"#d4b896",fontSize:16,margin:"0 0 8px",letterSpacing:"0.08em",textTransform:"uppercase"}}>Select a Link</h3>
              <p style={{fontFamily:"'IM Fell English',serif",fontStyle:"italic",color:"rgba(139,115,85,0.6)",fontSize:13,margin:0}}>Multiple hyperlinks were discovered. Which shall be examined?</p>
            </div>
            <OrnamentalDivider />
            <div style={{maxHeight:220,overflowY:"auto",display:"flex",flexDirection:"column",gap:6,marginBottom:16}}>
              {urlsInContent.map((u,i)=>(
                <button key={i} className="btn" onClick={()=>{setShowUrlPicker(false);if(result?.verdict==="SAFE"){doOpen(u);}else{setConfirmTarget({value:u});setShowConfirm(true);}}}
                  style={{background:"rgba(0,0,0,0.4)",border:"1px solid rgba(139,115,85,0.2)",borderRadius:3,padding:"10px 14px",fontFamily:"'Crimson Text',serif",fontSize:12,color:"#c8b89a",textAlign:"left",wordBreak:"break-all",cursor:"pointer",display:"flex",alignItems:"center",gap:8,letterSpacing:"0.02em"}}>
                  <span style={{flexShrink:0,opacity:0.5}}>🌐</span>{u}
                </button>
              ))}
            </div>
            <button className="btn" onClick={()=>setShowUrlPicker(false)}
              style={{width:"100%",background:"linear-gradient(135deg,#2a1f0e,#3d2d15)",color:"#d4b896",borderRadius:3,padding:"12px",fontFamily:"'Cinzel',serif",fontWeight:600,fontSize:12,border:"1px solid rgba(139,115,85,0.4)",letterSpacing:"0.15em",textTransform:"uppercase"}}>
              ✦ Withdraw
            </button>
          </div>
        </div>
      )}

      {/* CONFIRM MODAL */}
      {showConfirm && (
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.85)",backdropFilter:"blur(8px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:999,padding:20}}>
          <div style={{background:"linear-gradient(160deg,#1a0808,#0a0404)",borderRadius:4,padding:"32px 28px",maxWidth:420,width:"100%",boxShadow:"0 30px 80px rgba(0,0,0,0.9), 0 0 40px rgba(201,74,74,0.2)",border:"1px solid rgba(139,40,40,0.5)",animation:"popIn .35s ease",textAlign:"center"}}>
            <div style={{fontSize:48,marginBottom:14,animation:"float 2s ease-in-out infinite"}}>⚠️</div>
            <h3 style={{fontFamily:"'Cinzel',serif",fontWeight:700,color:"#e87a7a",fontSize:18,margin:"0 0 12px",letterSpacing:"0.08em",textTransform:"uppercase"}}>A Word of Caution</h3>
            <p style={{fontFamily:"'IM Fell English',serif",fontStyle:"italic",color:"rgba(200,184,154,0.7)",fontSize:14,margin:"0 0 14px",lineHeight:1.8}}>
              The Oracle has declared this address to be of <strong style={{color:cfg?.accent}}>{result?.verdict}</strong> character. Do you truly wish to proceed?
            </p>
            <div style={{background:"rgba(0,0,0,0.4)",borderRadius:3,padding:"10px 14px",fontSize:12,fontFamily:"'Crimson Text',serif",color:"#e87a7a",wordBreak:"break-all",border:"1px solid rgba(139,40,40,0.3)",marginBottom:20,letterSpacing:"0.02em"}}>
              {confirmTarget?.value || (input.startsWith("http") ? input : "https://" + input)}
            </div>
            <div style={{display:"flex",gap:10}}>
              <button className="btn" onClick={()=>setShowConfirm(false)}
                style={{flex:1,background:"linear-gradient(135deg,#1a2e1f,#2d4a35)",color:"#7ec896",borderRadius:3,padding:"12px",fontFamily:"'Cinzel',serif",fontWeight:600,fontSize:11,border:"1px solid rgba(74,124,89,0.4)",letterSpacing:"0.12em",textTransform:"uppercase"}}>
                ✦ Retreat to Safety
              </button>
              <button className="btn" onClick={()=>{doOpen(confirmTarget?.value||(input.startsWith("http")?input:"https://"+input));setShowConfirm(false);setConfirmTarget(null);}}
                style={{flex:1,background:"rgba(0,0,0,0.4)",color:"#c87878",border:"1px solid rgba(139,40,40,0.35)",borderRadius:3,padding:"12px",fontFamily:"'Cinzel',serif",fontWeight:600,fontSize:11,letterSpacing:"0.12em",textTransform:"uppercase"}}>
                ⚠ Proceed Anyway
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}