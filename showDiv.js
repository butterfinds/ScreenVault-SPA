function showDiv(divId) {
  const divs = ['div1', 'div2', 'div3', 'div4', 'div5'];
  divs.forEach(id => {
      const div = document.getElementById(id);
      if (id === divId) {
          div.classList.remove('hidden');
      } else {
          div.classList.add('hidden');
      }
  });
}

// Event listeners for navigation links
document.getElementById('link1').addEventListener('click', function() {
  showDiv('div1');
});
document.getElementById('link2').addEventListener('click', function() {
  showDiv('div2');
});
document.getElementById('link3').addEventListener('click', function() {
  showDiv('div3');
});
document.getElementById('link4').addEventListener('click', function() {
  showDiv('div4');
});
document.getElementById('link5').addEventListener('click', function() {
  showDiv('div5');
});
// Show div1 on page load
window.onload = function() {
  showDiv('div1');
};

