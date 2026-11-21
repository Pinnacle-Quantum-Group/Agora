// OAuth sessions use HttpOnly cookies. Operator token is required only for node administration.
window.agoraToken='';
window.agoraAuth=()=>{
 if(!window.agoraToken) window.agoraToken=prompt('Operator token (administration only):')||'';
 return window.agoraToken ? {'Authorization':'Bearer '+window.agoraToken} : {};
};
(async()=>{
 const box=document.getElementById('identity');
 try {const r=await fetch('/auth/me');if(r.ok){const u=await r.json();box.textContent='Signed in with '+u.provider+' · '+(u.email||u.subject.slice(0,12));return}}catch(e){}
 try {const r=await fetch('/auth/providers');const providers=await r.json();
   if(!providers.length){box.textContent='Local operator mode';return}
   box.replaceChildren();for(const p of providers){const a=document.createElement('a');a.href='/auth/login/'+p;a.textContent='Sign in with '+p+' ';box.append(a)}
 }catch(e){box.textContent='Login unavailable'}
})();
