function openModal(id){document.getElementById(id)?.classList.add('show')}
function closeModal(id){document.getElementById(id)?.classList.remove('show')}
window.addEventListener('click',e=>{document.querySelectorAll('.modal.show').forEach(m=>{if(e.target===m)m.classList.remove('show')})})
