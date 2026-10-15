'use strict';
const BASE='/store';
const $=s=>document.querySelector(s);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const money=n=>new Intl.NumberFormat('ko-KR').format(n)+'원';
const when=t=>new Date(t*1000).toLocaleString('ko-KR',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
const labels={received:'주문 접수',preparing:'배송 준비',shipping:'배송 중',delivered:'배송 완료'};
const statusOrder=Object.keys(labels);
const accounts=[['hana','김하나','고객 · 주문하고 내역을 확인해요'],['minjun','이민준','다른 고객 · 내 주문만 보여요'],['shipping','배송 담당','주문을 확인하고 배송을 준비해요'],['marketing','판매 분석 담당','개인정보 없이 판매 현황을 살펴요'],['operator','보호 과정 안내','암호문·권한·키 교체를 확인해요']];
const state={account:null,csrf:'',products:[],cart:{},category:'ALL',page:'shop',proof:null,migration:null,selected:'',orders:[]};
let noticeTimer, detailRequest=0, loginGeneration=0;
function toast(message){$('#toast').textContent=message;$('#toast').classList.add('show');clearTimeout(noticeTimer);noticeTimer=setTimeout(()=>$('#toast').classList.remove('show'),4500)}
async function api(path,body){
  const options={credentials:'same-origin',headers:{'X-Campus-Request':'1','X-CSRF-Token':state.csrf}};
  if(body!==undefined){options.method='POST';options.headers['Content-Type']='application/json';options.body=JSON.stringify(body)}
  let response;
  try{response=await fetch(BASE+'/api'+path,options)}catch{throw new Error('스토어에 연결할 수 없어요. 연결 상태를 확인해 주세요.')}
  let result;try{result=await response.json()}catch{throw new Error('응답을 읽을 수 없어요. 다시 시도해 주세요.')}
  if(!response.ok){if(response.status===401&&path!='/session'&&options.headers['X-CSRF-Token']===state.csrf){state.account=null;$('#detailBody').replaceChildren();showAccounts()}throw new Error(result.error||'요청을 처리하지 못했어요.')}
  return result;
}
function showAccounts(){if(!$('#accountDialog').open)$('#accountDialog').showModal()}
function allowedPages(){return state.account?.role==='customer'?['shop','orders']:state.account?.role==='shipping'?['shipping']:state.account?.role==='marketing'?['analytics']:['evidence','analytics']}
function navigation(){
  const titles={shop:'스토어',orders:'내 주문',shipping:'배송 관리',analytics:'판매 현황',evidence:'보호 과정'};
  $('#nav').innerHTML=allowedPages().map(p=>`<a class="nav-link ${state.page===p?'active':''}" href="#${p}">${titles[p]}</a>`).join('');
  $('#accountName').textContent=state.account?state.account.name+' · '+state.account.label:'시연 계정 선택';
}
function art(id){return BASE+'/art/'+id+'.svg'}
function shop(){
  const products=state.products.filter(p=>state.category==='ALL'||p.category===state.category);
  const count=Object.values(state.cart).reduce((a,b)=>a+b,0);
  const amount=state.products.reduce((a,p)=>a+p.price*(state.cart[p.id]||0),0);
  $('#main').innerHTML=`<section class="hero"><div class="hero-copy"><span class="eyebrow">THE CAMPUS COLLECTION · 2026</span><h1>좋아하는 일상에,<br>작은 캠퍼스 한 조각.</h1><p>강의실에서, 도서관에서, 그리고 주말에도.<br>우리의 하루와 자연스럽게 어울리는 물건들을 만나보세요.</p><a class="primary" href="#collection">컬렉션 둘러보기 <span>↗</span></a></div><div class="hero-art"><img src="${art('mug')}" alt="캠퍼스 로고 머그컵"><img class="floating" src="${art('bag')}" alt="캔버스 토트백"><div class="hero-note">MADE FOR<br>YOUR<br>EVERYDAY</div></div></section>
  <section id="collection"><div class="section-head"><div><h2>매일 함께할 물건들</h2><p>심플한 디자인에 담은 캠퍼스의 순간들</p></div><div class="filter-row">${[['ALL','전체'],['LIVING','리빙'],['BAGS','가방'],['APPAREL','의류'],['STATIONERY','문구']].map(([v,l])=>`<button class="chip ${state.category===v?'active':''}" data-action="category" data-id="${v}">${l}</button>`).join('')}</div></div><div class="products">${products.map(p=>`<article class="product"><div class="product-art ${p.color}"><span class="product-tag">${p.tag}</span><img src="${art(p.id)}" alt="${esc(p.name)}" loading="lazy"></div><div class="product-info"><span class="category">${p.category}</span><h3>${esc(p.name)}</h3><p>${esc(p.description)}</p><div class="product-bottom"><span class="price">${money(p.price)}</span><button class="add-button" data-action="add" data-id="${p.id}" aria-label="${esc(p.name)} 장바구니에 담기">+</button></div></div></article>`).join('')}</div></section>
  <div class="benefits"><div class="benefit"><span>♧</span><div><strong>개인정보는 안전하게</strong><p>배송정보는 암호화해서 보관해요.</p></div></div><div class="benefit"><span>□</span><div><strong>작은 물건, 오래 쓰는 마음</strong><p>일상에 자연스럽게 스며드는 디자인.</p></div></div><div class="benefit"><span>↗</span><div><strong>캠퍼스에서 시작하는 이야기</strong><p>우리의 일상을 함께 만들어 가요.</p></div></div></div>
  ${count?`<div class="cart-bar"><div><strong>${count}개의 물건 · ${money(amount)}</strong><p>가상 상품 · 모의 주문</p></div><div><button data-action="clear-cart" aria-label="장바구니 비우기">비우기</button> <button data-action="checkout">주문하기 →</button></div></div>`:''}`;
}
function itemsHTML(order){return order.items.map(i=>`<div class="order-item"><img src="${art(i.id)}" alt=""><div><h3>${esc(i.name)}</h3><p>수량 ${i.quantity}개</p></div><strong>${money(i.price*i.quantity)}</strong></div>`).join('')}
function empty(title,detail,shopLink=false){return `<div class="empty"><span class="empty-icon">▱</span><strong>${title}</strong><p>${detail}</p>${shopLink?'<a class="primary" href="#shop">스토어 둘러보기 →</a>':''}</div>`}
async function ordersPage(shipping){
  const result=await api('/orders');state.orders=result.orders;
  $('#main').innerHTML=`<div class="page-heading"><span class="eyebrow">${shipping?'FULFILLMENT':'MY ORDERS'}</span><div class="heading-row"><div><h1>${shipping?'배송을 준비하는 공간':'기다리는 즐거움, 내 주문'}</h1><p>${shipping?'접수된 주문을 확인하고, 고객에게 도착할 준비를 해 주세요.':'주문한 물건들이 어디쯤 왔는지 확인해 보세요.'}</p></div><button class="secondary" data-action="refresh">새로고침</button></div></div>
  ${shipping?`<div class="filter-row">${[['all','전체'],...Object.entries(labels)].map(([v,l])=>`<button class="chip ${v==='all'?'active':''}" data-action="status-filter" data-id="${v}">${l}</button>`).join('')}</div>`:''}
  <div id="orderList">${result.orders.length?result.orders.map(o=>orderCard(o,shipping)).join(''):empty('아직 주문이 없어요',shipping?'고객 계정에서 첫 주문을 접수해 주세요.':'마음에 드는 물건을 골라 첫 주문을 남겨 보세요.',!shipping)}</div>`;
}
function orderCard(o,shipping){const idx=statusOrder.indexOf(o.status);return `<article class="order-card"><div class="order-head"><div><span class="order-id">${esc(o.id)}</span><p class="order-time">${when(o.created)}</p></div><span class="badge ${o.status==='shipping'?'blue':''}">${labels[o.status]}</span></div>${itemsHTML(o)}<div class="order-foot"><span class="protected">♧ 배송정보는 안전하게 보호되고 있어요.</span><div class="order-actions">${shipping?`<button class="secondary" data-action="recipient" data-id="${o.id}">배송정보 확인</button>${idx<3?`<button class="primary" data-action="status" data-id="${o.id}" data-status="${statusOrder[idx+1]}">${labels[statusOrder[idx+1]]}으로 변경 →</button>`:''}`:`<strong>총 ${money(o.amount)}</strong>`}</div></div>${!shipping?`<div class="status-track">${statusOrder.map((s,i)=>`<div class="status-step ${i<=idx?'done':''}">${labels[s]}</div>`).join('')}</div>`:''}</article>`}
async function analytics(){
  const [data,orders]=await Promise.all([api('/analytics'),api('/orders')]);state.orders=orders.orders;
  const max=Math.max(1,...data.products.map(p=>p.quantity));
  $('#main').innerHTML=`<div class="page-heading"><span class="eyebrow">SALES OVERVIEW</span><div class="heading-row"><div><h1>숫자로 만나는 스토어</h1><p>고객의 개인정보 없이도, 우리의 판매 흐름을 이해할 수 있어요.</p></div><button class="secondary" data-action="refresh">새로고침</button></div></div><div class="stat-grid"><div class="stat-card"><p>접수된 주문</p><strong>${data.count}<small> 건</small></strong></div><div class="stat-card"><p>누적 모의 매출</p><strong>${money(data.amount)}</strong></div><div class="stat-card"><p>배송 완료</p><strong>${data.delivered}<small> 건</small></strong></div></div><div class="panel"><h2>어떤 물건을 좋아할까요?</h2><p>실제 접수된 시연 주문의 상품별 수량입니다.</p>${data.products.map(p=>`<div class="chart-row"><span>${esc(p.name)}</span><div class="bar"><div class="bar-fill" data-percent="${Math.round(p.quantity/max*100)}"></div></div><strong>${p.quantity}개</strong></div>`).join('')}</div>
  <div class="panel"><h2>판매 분석에 배송주소가 필요할까요?</h2><p>분석 서비스는 판매량을 집계하지만, 배송정보를 복호화할 권한은 없어요. 실제 KMS 응답으로 확인해 보세요.</p>${proofControls(orders.orders,true)}<div id="proofResult">${proofHTML()}</div></div>`;
  document.querySelectorAll('[data-percent]').forEach(e=>e.style.width=e.dataset.percent+'%');
}
function proofControls(orders,marketingOnly=false){return orders.length?`<label class="sr-only" for="proofOrder">확인할 주문</label><select id="proofOrder">${orders.map(o=>`<option value="${o.id}" ${o.id===state.selected?'selected':''}>${esc(o.id)} · v${o.version} · ${labels[o.status]}</option>`).join('')}</select><div class="probe-controls"><button class="secondary" data-action="probe" data-kind="marketing">분석 서비스로 조회 시도</button>${marketingOnly?'':'<button class="secondary" data-action="probe" data-kind="current">현재 암호문 확인</button><button class="secondary" data-action="probe" data-kind="previous">갱신 전 암호문 확인</button><button class="secondary" data-action="probe" data-kind="tamper">변조 감지 확인</button>'}</div>`:empty('확인할 주문이 없어요','고객 계정에서 주문을 접수하면 권한 차이를 확인할 수 있어요.')}
function proofHTML(){
  const p=state.proof;if(!p)return '';
  const expectedDenial=p.kind==='marketing'&&p.kms_status===403;
  const titles={allowed:p.kind==='marketing'?'예상과 달리 접근이 허용됐습니다. 권한 설정을 확인하세요.':'복호화 요청이 허용되었습니다.',denied:'이 서비스의 조회 권한이 없습니다.',invalid:'이 암호문은 사용할 수 없습니다.',unavailable:'서비스 응답을 확인할 수 없습니다.'};
  const desc=p.kind==='marketing'?'분석 서비스의 실제 요청 결과입니다. 화면에서 값을 숨기기만 한 결과가 아닙니다.':p.kind==='previous'?'보관된 갱신 전 암호문에 대한 실제 결과입니다. 최소 복호화 버전 정책을 적용해야 차단됩니다.':p.kind==='tamper'?'저장된 값을 바꾸지 않고 암호문 사본을 변조하여 요청했습니다.':'평문을 화면에 출력하지 않고, 현재 주문의 복호화 가능 여부만 확인했습니다.';
  return `<div class="proof-result ${expectedDenial?'denied':p.outcome==='unavailable'||(p.kind==='marketing'&&p.kms_status===200)?'alert':''}"><span class="badge ${p.kms_status===200?'blue':p.kms_status===403?'neutral':'red'}">${p.kms_status?`HTTP ${p.kms_status}`:'응답 없음'} · ${esc(p.service)}</span><strong>${titles[p.outcome]}</strong><p>${desc}</p><p>${esc(p.order_id)} · 암호문 v${p.version}</p></div>`;
}
async function evidence(){
  const data=await api('/evidence');state.orders=data.orders;
  const versions=[...new Set(data.orders.map(o=>o.version))].sort((a,b)=>a-b);
  $('#main').innerHTML=`<div class="page-heading"><span class="eyebrow">BEHIND THE STORE</span><div class="heading-row"><div><h1>평범한 주문 뒤의 보호 과정</h1><p>저장된 암호문과 실제 KMS 호출 결과를 함께 살펴보세요.</p></div><button class="secondary" data-action="refresh">새로고침</button></div></div>
  <div class="stat-grid"><div class="stat-card"><p>암호화해 보관한 주문</p><strong>${data.orders.length} 건</strong></div><div class="stat-card"><p>저장된 암호문 버전</p><strong>${versions.length?versions.map(v=>'v'+v).join(' · '):'—'}</strong></div><div class="stat-card"><p>전용 보호 키</p><strong class="small">${esc(data.key)}</strong></div></div>
  <div class="split"><section class="panel"><h2>같은 데이터, 다른 권한</h2><p>네 백엔드는 각각 다른 ServiceAccount로 KMS에 접근합니다.</p><table><thead><tr><th>서비스</th><th>허용된 KMS 작업</th></tr></thead><tbody><tr><td>주문 접수</td><td>encrypt</td></tr><tr><td>배송 조회</td><td>decrypt</td></tr><tr><td>판매 분석</td><td>없음 · 거부 확인</td></tr><tr><td>보호 버전 갱신</td><td>rewrap</td></tr></tbody></table><p class="fine">이 표는 배포한 권한 의도입니다. 아래 요청 결과로 실제 적용을 확인하세요.</p></section><section class="panel"><h2>기존 주문의 보호 버전 갱신</h2><p>먼저 KMS 관리 콘솔에서 <code>${esc(data.key)}</code> 키를 회전하세요. 이후 기존 주문을 새 버전으로 옮깁니다.</p><button class="primary" data-action="migrate" ${data.orders.length?'':'disabled'}>기존 주문 보호 버전 갱신 →</button><p class="details-note">rewrap 결과를 DB에 실제로 교체합니다. 앱은 평문을 반환받지 않습니다. 모든 주문의 갱신을 확인한 뒤 관리 콘솔에서 최소 복호화 버전을 변경하세요.</p>${state.migration?`<p class="${state.migration.failed.length?'error-banner':'muted'}">총 ${state.migration.total}건 중 ${state.migration.updated}건 갱신, ${state.migration.failed.length}건 실패. ${state.migration.failed.length?'실패한 주문은 기존 값을 유지합니다.':''}</p>`:''}</section></div>
  <section class="panel"><h2>실제 요청으로 확인하기</h2><p>반환된 상태를 그대로 표시합니다. 연결 장애를 권한 차단 성공으로 표시하지 않습니다.</p>${proofControls(data.orders)}<div id="proofResult">${proofHTML()}</div></section>
  <section class="panel"><h2>앱 DB에는 무엇이 저장되어 있을까요?</h2><p>SQLite에서 읽은 실제 저장값입니다. 배송정보 원문과 KMS 키 자료는 보관하지 않습니다.</p>${data.orders.length?data.orders.slice(0,12).map(o=>`<details><summary>${esc(o.id)} · <span class="badge">보호 버전 v${o.version}</span> · ${money(o.amount)}</summary><p class="details-note">일반 필드: 상품·수량·금액·배송 상태 · 보호 필드: 이름·연락처·주소를 묶은 암호문</p><pre class="cipher">${esc(o.ciphertext)}</pre></details>`).join(''):empty('아직 저장된 주문이 없어요','스토어에서 첫 주문을 만들어 보세요.')}</section>
  <section class="panel"><h2>최근 보호 요청</h2><p>이 앱의 요청 결과 기록입니다. KMS 전체의 Transit 감사 로그를 구현한 것은 아닙니다.</p><div class="table-wrap"><table><thead><tr><th>시각</th><th>서비스</th><th>작업</th><th>결과</th><th>주문</th></tr></thead><tbody>${data.events.map(e=>`<tr><td>${when(e.created)}</td><td>${esc(e.service)}</td><td><code>${esc(e.operation)}</code></td><td><span class="badge ${e.status===200?'':e.status===403?'neutral':'red'}">${e.status}</span></td><td>${esc(e.order_id)}</td></tr>`).join('')||'<tr><td colspan="5">아직 요청 기록이 없습니다.</td></tr>'}</tbody></table></div></section>`;
}
async function render(){
  if(!state.account)return;
  const requested=location.hash.slice(1);
  if(requested==='collection'){document.getElementById('collection')?.scrollIntoView({behavior:'smooth'});return}
  state.page=allowedPages().includes(requested)?requested:allowedPages()[0];navigation();
  try{if(state.page==='shop')shop();else if(state.page==='orders')await ordersPage(false);else if(state.page==='shipping')await ordersPage(true);else if(state.page==='analytics')await analytics();else await evidence()}
  catch(error){$('#main').innerHTML=`<div class="page-heading"><h1>잠시 연결을 확인하고 있어요.</h1></div><div class="error-banner">${esc(error.message)}</div><button class="primary" data-action="refresh">다시 시도</button>`}
}
function openCheckout(){
  const items=state.products.filter(p=>state.cart[p.id]).map(p=>({...p,quantity:state.cart[p.id]}));
  if(!items.length)return;
  $('#checkoutItems').innerHTML=itemsHTML({items});
  $('#checkoutTotal').innerHTML=`<span>총 주문 금액</span><strong>${money(items.reduce((n,p)=>n+p.price*p.quantity,0))}</strong>`;
  $('#checkoutDialog').showModal();
}
document.addEventListener('click',async event=>{
  const close=event.target.closest('[data-close]');if(close){if(close.dataset.close==='accountDialog'&&!state.account)return;$('#'+close.dataset.close).close();return}
  const button=event.target.closest('[data-action]');if(!button)return;
  const action=button.dataset.action;button.disabled=true;
  try{
    if(action==='login'){
      loginGeneration++;
      const result=await api('/login',{account:button.dataset.id});state.account=result.account;state.csrf=result.csrf;state.cart={};state.proof=null;state.migration=null;
      clearTimeout(noticeTimer);$('#toast').classList.remove('show');$('#checkoutForm').reset();clearRecipient();$('#accountDialog').close();
      state.products=(await api('/catalog')).products;location.hash=allowedPages()[0];await render();
    }else if(action==='category'){state.category=button.dataset.id;shop()}
    else if(action==='add'){const id=button.dataset.id;state.cart[id]=Math.min(9,(state.cart[id]||0)+1);shop();toast('장바구니에 담았어요.')}
    else if(action==='clear-cart'){state.cart={};shop()}
    else if(action==='checkout')openCheckout();
    else if(action==='refresh')await render();
    else if(action==='status-filter'){
      document.querySelectorAll('[data-action="status-filter"]').forEach(b=>b.classList.toggle('active',b===button));
      const rows=state.orders.filter(o=>button.dataset.id==='all'||o.status===button.dataset.id);$('#orderList').innerHTML=rows.length?rows.map(o=>orderCard(o,true)).join(''):empty('이 단계의 주문이 없어요','다른 배송 단계를 선택해 보세요.');
    }else if(action==='recipient'){
      const requestId=++detailRequest;
      $('#detailBody').innerHTML='<p class="muted">보호된 배송정보를 확인하고 있어요…</p>';$('#detailDialog').showModal();
      try{const r=await api('/orders/'+button.dataset.id+'/recipient',{});if(requestId===detailRequest&&$('#detailDialog').open)$('#detailBody').innerHTML=`<span class="badge">배송 서비스 · HTTP ${r.kms_status}</span><div class="recipient-box"><dl>${[['name','받는 사람'],['phone','연락처'],['address','배송주소']].map(([k,l])=>`<dt>${l}</dt><dd>${esc(r.recipient[k])}</dd>`).join('')}</dl></div><p class="fine center">배송을 위해 요청한 정보입니다. 창을 닫으면 표시한 원문을 지웁니다.</p>`}catch(e){if(requestId===detailRequest&&$('#detailDialog').open)$('#detailBody').innerHTML=`<div class="error-banner">배송정보를 확인할 수 없습니다.<br>${esc(e.message)}</div>`}
    }else if(action==='status'){await api('/orders/'+button.dataset.id+'/status',{status:button.dataset.status});toast('배송 상태를 변경했어요.');await render()}
    else if(action==='probe'){state.selected=$('#proofOrder').value;state.proof=await api('/probe',{order_id:state.selected,kind:button.dataset.kind});$('#proofResult').innerHTML=proofHTML()}
    else if(action==='migrate'){state.migration=await api('/migrate',{});await evidence();toast(`${state.migration.updated}건의 보호 버전을 갱신했어요.`)}
  }catch(error){toast(error.message)}finally{button.disabled=false}
});
$('#accountButton').addEventListener('click',showAccounts);
$('#accounts').innerHTML=accounts.map(([id,name,desc])=>`<button class="account-choice" data-action="login" data-id="${id}"><strong>${name}</strong><span>${desc}</span></button>`).join('');
$('#accountDialog').addEventListener('cancel',event=>{if(!state.account)event.preventDefault()});
function clearRecipient(){detailRequest++;$('#detailBody').replaceChildren()}
$('#detailDialog').addEventListener('close',clearRecipient);
$('#checkoutDialog').addEventListener('close',()=>$('#checkoutForm').reset());
$('#sampleButton').addEventListener('click',()=>{const f=$('#checkoutForm');f.elements.name.value=state.account?.name||'가상 고객';f.elements.phone.value='000-0000-0000';f.elements.address.value='가상시 캠퍼스로 100, 시연관 101호'});
$('#checkoutForm').addEventListener('submit',async event=>{
  event.preventDefault();const button=event.submitter;button.disabled=true;
  try{const f=new FormData(event.target);const result=await api('/orders',{items:Object.entries(state.cart).map(([id,quantity])=>({id,quantity})),recipient:{name:f.get('name'),phone:f.get('phone'),address:f.get('address')}});state.cart={};$('#checkoutDialog').close();event.target.reset();location.hash='orders';await render();toast(`${result.order.id} 주문이 안전하게 접수됐어요.`)}catch(error){toast(error.message)}finally{button.disabled=false}
});
window.addEventListener('hashchange',render);
window.addEventListener('pagehide',()=>{clearRecipient();$('#checkoutForm').reset()});
document.addEventListener('visibilitychange',()=>{if(document.hidden)clearRecipient()});
(async()=>{const generation=loginGeneration;try{const s=await api('/session');if(generation!==loginGeneration)return;state.account=s.account;state.csrf=s.csrf;const catalog=await api('/catalog');if(generation!==loginGeneration)return;state.products=catalog.products;await render()}catch{if(generation!==loginGeneration)return;$('#main').innerHTML=`<section class="hero"><div class="hero-copy"><span class="eyebrow">WELCOME TO CAMPUS STORE</span><h1>캠퍼스의 일상을<br>안전하게 이어갑니다.</h1><p>시연 계정을 선택하고 스토어를 둘러보세요.</p></div><div class="hero-art"><img src="${art('mug')}" alt="캠퍼스 머그컵"></div></section>`;showAccounts()}})();
