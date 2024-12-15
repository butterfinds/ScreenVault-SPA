document.querySelectorAll('.star-rating-input span').forEach((star) => {
    star.addEventListener('click', () => {
      const value = star.getAttribute('data-value');
      document.getElementById('rating-value').value = value;
  
      // Highlight selected stars
      star.parentElement.querySelectorAll('span').forEach((s) => {
        s.classList.toggle('selected', s.getAttribute('data-value') <= value);
      });
    });
  });