// Renderizado del lado cliente: solo asigna constantes o texto.
function showBanner(el) {
  el.innerHTML = '<strong>Bienvenido</strong>';      // constante, no hay datos externos
}
function showName(el, name) {
  el.textContent = name;                              // textContent: no interpreta HTML
}
module.exports = { showBanner, showName };
