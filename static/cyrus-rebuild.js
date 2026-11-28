/* CYRUS screen/menu interaction layer */
(function(){
 'use strict';
 const closeLayers=()=>{
  let closed=false;
  const selectors=['#cyrusEmojiPanel','#cyrusAttachMenu','#cyrusRoomMenu','.message.context-open .message-context','.setting-edit-overlay.open','.setting-avatar-editor.open'];
  selectors.forEach(sel=>document.querySelectorAll(sel).forEach(el=>{
   if(sel==='#cyrusEmojiPanel'){if(el.style.display!=='none'){el.style.display='none';closed=true;}}
   else if(sel==='#cyrusAttachMenu'||sel==='#cyrusRoomMenu'){if(!el.hidden){el.hidden=true;closed=true;}}
   else if(sel.includes('message-context')){el.setAttribute('aria-hidden','true');el.closest('.message')?.classList.remove('context-open');closed=true;}
   else if(el.classList.contains('open')){el.classList.remove('open');closed=true;}
  }));
  return closed;
 };
 window.cyrusCloseOverlays=closeLayers;
 document.addEventListener('keydown',e=>{if(e.key==='Escape'&&closeLayers())e.stopPropagation();},true);
 document.addEventListener('click',e=>{
  const action=e.target.closest('[data-cyrus-action]');
  if(!action)return;
  const name=action.getAttribute('data-cyrus-action');
  if(name==='close-menu'){closeLayers();return;}
  if(name==='back'){if(closeLayers())return;if(window.cyrusGoBack)window.cyrusGoBack();else history.back();}
 },true);
 // Keep back navigation predictable: close transient panels first, then return to the previous screen.
 let handling=false;
 window.addEventListener('popstate',()=>{
  if(handling)return;
  if(closeLayers()){
   handling=true;history.pushState({cyrusLayerGuard:true},'',location.href);
   setTimeout(()=>handling=false,80);
  }
 });
 // Fix common non-button menu rows so touch activation works consistently.
 document.querySelectorAll('[role="button"],.chat-row,.message').forEach(el=>{el.style.webkitTapHighlightColor='transparent';});
})();
