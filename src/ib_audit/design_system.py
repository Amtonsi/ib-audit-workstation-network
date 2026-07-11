from __future__ import annotations


APP_COLORS = {
    "canvas": "#EEF6F5",
    "header": "#123C3A",
    "header_end": "#1D4F63",
    "header_muted": "#BFE3DF",
    "rail": "#F6FAF9",
    "panel": "#FFFFFF",
    "surface_soft": "#F4F9F8",
    "border": "#D5E2E5",
    "text": "#173238",
    "muted": "#60747B",
    "teal": "#0F766E",
    "teal_hover": "#115E59",
    "blue": "#2563EB",
    "violet": "#6D4AFF",
    "amber": "#B45309",
    "red": "#B91C1C",
    "green": "#15803D",
    "console": "#102136",
}


REPORT_THEME_STYLE = """
<style id="readme-design-system">
:root{
  --ink:#173238;
  --muted:#60747b;
  --canvas:#eef6f5;
  --panel:#ffffff;
  --line:#d5e2e5;
  --teal:#0f766e;
  --teal-dark:#123c3a;
  --teal-end:#1d4f63;
  --blue:#2563eb;
  --violet:#6d4aff;
  --amber:#b45309;
  --red:#b91c1c;
  --green:#15803d;
  --console:#102136;
  --shadow:0 12px 32px rgba(23,50,56,.10);
  --shadow-strong:0 18px 44px rgba(23,50,56,.14);
}
html{scroll-behavior:smooth;background:#eef6f5}
body{
  color:var(--ink);
  font-family:"Segoe UI Variable Text","Aptos","Segoe UI",sans-serif;
  background:
    radial-gradient(circle at 5% 2%,rgba(94,234,212,.18),transparent 26rem),
    radial-gradient(circle at 96% 12%,rgba(37,99,235,.10),transparent 30rem),
    linear-gradient(135deg,#edf8f6 0%,#f7fafc 52%,#edf3fb 100%);
  background-attachment:fixed;
}
aside{
  background:linear-gradient(180deg,var(--teal-dark) 0%,var(--teal-end) 100%)!important;
  border-right:0!important;
  box-shadow:12px 0 34px rgba(18,60,58,.16);
}
aside .brand{color:#fff!important;font-weight:800;letter-spacing:-.02em}
aside .brand-subtitle,aside .nav-title,aside .nav-empty{color:#bfe3df!important}
aside a{
  color:#d8f4ef!important;
  border-radius:10px;
  border:1px solid transparent;
  transition:background .18s ease,border-color .18s ease,transform .18s ease;
}
aside a:hover,aside a.active{
  color:#fff!important;
  background:rgba(255,255,255,.12)!important;
  border-color:rgba(125,211,199,.45);
  transform:translateX(2px);
}
main{max-width:1480px}
h1,h2,h3,h4{color:var(--ink);letter-spacing:-.018em}
.eyebrow{color:var(--teal)!important;font-weight:800;letter-spacing:.12em}
section,.card,.filter-panel,.document-section,.finding-card,.object-card,
.network-dashboard-card,.network-map-panel,.network-packet-report{
  border-color:var(--line)!important;
  border-radius:16px!important;
  background:rgba(255,255,255,.97);
  box-shadow:var(--shadow);
}
.hero{
  color:#fff;
  border:0!important;
  border-radius:20px!important;
  background:linear-gradient(105deg,var(--teal-dark),var(--teal-end))!important;
  box-shadow:var(--shadow-strong);
  overflow:hidden;
  position:relative;
}
.hero::after{
  content:"";
  position:absolute;
  right:-90px;
  top:-130px;
  width:340px;
  height:340px;
  border-radius:50%;
  background:radial-gradient(circle,rgba(94,234,212,.25),rgba(94,234,212,0) 68%);
  pointer-events:none;
}
.hero h1,.hero h2,.hero h3,.hero .eyebrow{color:#fff!important}
.hero .meta,.hero p{color:#c9e8e4}
.hero .kpi{
  border-color:rgba(191,227,223,.28)!important;
  background:rgba(255,255,255,.10)!important;
  box-shadow:none;
}
.hero .kpi strong,.hero .kpi span{color:#fff!important}
.kpis{gap:12px!important}
.kpi{
  min-height:92px;
  padding:16px!important;
  border:1px solid var(--line)!important;
  border-radius:14px!important;
  background:#fff;
  box-shadow:0 8px 22px rgba(23,50,56,.07);
}
.kpi strong{color:var(--teal-dark)!important;font-size:25px!important}
.kpi span{color:var(--muted)!important;font-weight:650}
.pill,.batch-status,.status-dot,.severity,.object-status,.status,.traffic-badge,
.protocol-badge,.host-pill,.count{
  border-radius:999px!important;
  font-weight:750!important;
  box-shadow:none!important;
}
.filters,.filter-row,.document-tools{gap:8px!important}
.filters button,.filter-row button,.document-tools a,.search{
  min-height:36px;
  border:1px solid var(--line)!important;
  border-radius:10px!important;
  background:#fff!important;
  color:var(--teal)!important;
  font-weight:750!important;
  box-shadow:0 5px 14px rgba(23,50,56,.06);
}
.filters button:hover,.filter-row button:hover,.document-tools a:hover{
  color:#fff!important;
  border-color:var(--teal)!important;
  background:var(--teal)!important;
}
table{
  border-collapse:separate!important;
  border-spacing:0;
  border:1px solid var(--line);
  border-radius:12px;
  overflow:hidden;
  background:#fff;
}
th{
  color:#40575f!important;
  background:#edf4f4!important;
  border-color:var(--line)!important;
  font-size:12px;
  letter-spacing:.02em;
}
td{border-color:#e7edef!important}
tr:hover td{background:#f2f8f7}
.finding,.finding-card,.host-finding{border-left-width:5px!important}
.finding-card,.host-finding,.object-card{transition:transform .18s ease,box-shadow .18s ease}
.finding-card:hover,.host-finding:hover,.object-card:hover{
  transform:translateY(-2px);
  box-shadow:var(--shadow-strong);
}
.network-dashboard{gap:14px!important}
.network-dashboard-card{padding:16px!important}
.network-dashboard-card h3{color:var(--teal-dark)!important}
.network-overview{
  border:1px solid #b7d9d5!important;
  border-left:5px solid var(--teal)!important;
  border-radius:14px!important;
  background:linear-gradient(110deg,#e9f8f4,#eff6ff)!important;
  box-shadow:0 9px 24px rgba(15,118,110,.08);
}
.network-map-panel{
  border-color:#b7d9d5!important;
  box-shadow:0 16px 38px rgba(23,50,56,.12)!important;
}
.network-map-panel h3{
  color:var(--teal-dark)!important;
  background:linear-gradient(90deg,#e9f8f4,#eff6ff 58%,#ecfeff)!important;
}
.network-map-svg{background:#f8fafc!important}
.network-map-bg{fill:#f4f9f8!important}
.network-map-grid{stroke:rgba(71,85,105,.12)!important}
.network-packet-report{padding:16px!important;background:#fbfdfd!important}
.packet-list-collapsed{
  border-color:var(--line)!important;
  border-radius:14px!important;
  overflow:hidden;
  box-shadow:0 8px 22px rgba(23,50,56,.07);
}
.packet-list-collapsed>summary{
  color:var(--teal-dark)!important;
  background:linear-gradient(90deg,#edf7f5,#f3f7fb)!important;
}
.packet-samples pre,.packet-hex{
  color:#dcecff!important;
  background:var(--console)!important;
  border:1px solid #263b55;
  border-radius:10px!important;
}
.protocol-http{background:#ef4444!important}
.protocol-tls{background:#15803d!important}
.protocol-dns{background:#b45309!important}
.protocol-quic{background:#0891b2!important}
.protocol-tcp{background:#2563eb!important}
.protocol-udp{background:#f59e0b!important}
.protocol-arp{background:#0f766e!important}
.document-section>details>summary{
  color:var(--teal-dark);
  background:linear-gradient(90deg,#edf7f5,#f7fafc)!important;
}
.banner{border-radius:14px!important;box-shadow:0 8px 22px rgba(23,50,56,.07)}
.coverage-bar{border-radius:999px;overflow:hidden;background:#dce7e8!important}
@media(max-width:900px){
  body{background:#eef6f5}
  aside{
    position:static!important;
    width:auto!important;
    max-height:260px!important;
    overflow:auto!important;
    padding:18px!important;
    display:flex!important;
    flex-wrap:wrap;
    align-items:center;
    align-content:flex-start;
    gap:8px;
    box-shadow:none;
  }
  aside .brand{width:100%;margin:0!important}
  aside .brand-subtitle{width:100%;margin:0 0 6px!important}
  aside .nav-title{width:auto;margin:4px 2px!important}
  aside a{
    display:inline-flex!important;
    width:auto!important;
    margin:0!important;
    padding:7px 10px!important;
    font-size:12px;
  }
  main{padding:12px!important}
  section,.card,.document-section{border-radius:13px!important}
}
@media print{
  body{background:#fff!important}
  aside{background:#fff!important;color:#000!important;box-shadow:none}
  section,.card,.document-section,.finding-card,.object-card{box-shadow:none!important}
}
</style>
"""
