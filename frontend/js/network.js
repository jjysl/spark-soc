// NET PROTO
const proto=[{label:'HTTPS / 443',pct:62,color:'#3b82f6'},{label:'DNS / 53',pct:18,color:'#8b5cf6'},{label:'SMB / 445',pct:8,color:'#da291c'},{label:'SSH / 22',pct:6,color:'#10b981'},{label:'Other',pct:6,color:'#9ca3af'}];
const npd=document.getElementById('net-proto');
if(npd) proto.forEach(p=>{npd.innerHTML+=`<div class="nbar"><span class="nl">${p.label}</span><div class="ntrack"><div class="nfill" style="width:${p.pct}%;background:${p.color}"></div></div><span class="nval">${p.pct}%</span></div>`;});

// TOPOLOGY
const svg=document.getElementById('topo-svg');
if(svg){
  const nodes=[
    {x:220,y:85,r:22,label:'FortiGate',color:'#da291c'},
    {x:75,y:40,r:15,label:'VLAN 10',color:'#3b82f6'},
    {x:75,y:130,r:15,label:'VLAN 20',color:'#3b82f6'},
    {x:365,y:40,r:15,label:'Internet',color:'#6b7280'},
    {x:365,y:130,r:15,label:'FortiAnalyzer',color:'#10b981'},
    {x:148,y:40,r:11,label:'WRK-042',color:'#da291c'},
  ];
  [[0,1],[0,2],[0,3],[0,4],[1,5]].forEach(([a,b])=>{
    const n1=nodes[a],n2=nodes[b],anom=n2.label==='WRK-042';
    const l=document.createElementNS('http://www.w3.org/2000/svg','line');
    l.setAttribute('x1',n1.x);l.setAttribute('y1',n1.y);l.setAttribute('x2',n2.x);l.setAttribute('y2',n2.y);
    l.setAttribute('stroke',anom?'#da291c':'#c8cdd5');l.setAttribute('stroke-width',anom?'2':'1.5');
    if(anom)l.setAttribute('stroke-dasharray','5 3');
    svg.appendChild(l);
  });
  nodes.forEach(n=>{
    const g=document.createElementNS('http://www.w3.org/2000/svg','g');
    const c=document.createElementNS('http://www.w3.org/2000/svg','circle');
    c.setAttribute('cx',n.x);c.setAttribute('cy',n.y);c.setAttribute('r',n.r);c.setAttribute('fill',n.color);
    const t=document.createElementNS('http://www.w3.org/2000/svg','text');
    t.setAttribute('x',n.x);t.setAttribute('y',n.y+n.r+13);t.setAttribute('text-anchor','middle');
    t.setAttribute('font-size','9');t.setAttribute('fill','#4a5568');t.setAttribute('font-family','Inter,sans-serif');
    t.textContent=n.label;
    g.appendChild(c);g.appendChild(t);svg.appendChild(g);
  });
}

// UEBA
const uebaData=[
  {init:'FC',name:'f.carvalho',action:'Mass file access · outside business hours',risk:'High Risk',rb:'bcrit',score:92,sc:'shi'},
  {init:'PM',name:'p.mendes',action:'Privilege escalation attempt via RunAs',risk:'Elevated',rb:'bhigh',score:78,sc:'shi'},
  {init:'AB',name:'a.bastos',action:'Login from unusual location',risk:'Moderate',rb:'bmed',score:55,sc:'smed'},
  {init:'RN',name:'r.nunes',action:'High-volume DNS queries — possible tunneling',risk:'Moderate',rb:'bmed',score:47,sc:'smed'},
  {init:'CL',name:'c.lima',action:'Normal behavior pattern',risk:'Low',rb:'blow',score:12,sc:'slow'},
  {init:'JS',name:'j.santos',action:'Normal behavior pattern',risk:'Low',rb:'blow',score:8,sc:'slow'},
];
const ul=document.getElementById('ueba-list');
if(ul) uebaData.forEach(u=>{
  ul.innerHTML+=`<div class="urow"><div class="uav">${u.init}</div><div class="uinfo"><div class="uname">${u.name}</div><div class="uact">${u.action}</div></div><div style="display:flex;align-items:center;gap:6px"><span class="badge ${u.rb}">${u.risk}</span><span class="uscr ${u.sc}">${u.score}</span></div></div>`;
});

