const searchInput = document.getElementById('searchInput');

// References to the sections containing movie cards
const popularMoviesSection = document.querySelector('.popularMovies');
const newMoviesSection = document.querySelector('.newMovies');
const moreMoviesSection = document.querySelector('.moreMovies');

// Function to filter movie cards based on search query
searchInput.addEventListener('input', () => {
  const query = searchInput.value.toLowerCase().trim();
  const movieCards = document.querySelectorAll('.movie-card');
  let hasResults = false; // Flag to track if any movie matches the query

  // Loop through all movie cards to check if they match the search query
  movieCards.forEach(card => {
    const title = card.querySelector('h3').textContent.toLowerCase(); // Movie title
    const genres = card.querySelector('.movie-genre')?.textContent.toLowerCase(); // Genres

    // Check if the query matches the title or genres
    if (title.includes(query) || (genres && genres.includes(query))) {
      card.style.display = 'block'; // Show matching card
      hasResults = true;
    } else {
      card.style.display = 'none'; // Hide non-matching card
    }
  });

  // Adjust visibility of sections based on matching cards
  if (query === '') {
    popularMoviesSection.style.display = 'block';
    newMoviesSection.style.display = 'block';
    moreMoviesSection.style.display = 'block';

    // Scroll to the top when search is cleared
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } else {
    // Only show sections with at least one visible movie card
    const popularMoviesVisible = [...popularMoviesSection.querySelectorAll('.movie-card')].some(card => card.style.display !== 'none');
    const newMoviesVisible = [...newMoviesSection.querySelectorAll('.movie-card')].some(card => card.style.display !== 'none');
    const moreMoviesVisible = [...moreMoviesSection.querySelectorAll('.movie-card')].some(card => card.style.display !== 'none');

    popularMoviesSection.style.display = popularMoviesVisible ? 'block' : 'none';
    newMoviesSection.style.display = newMoviesVisible ? 'block' : 'none';
    moreMoviesSection.style.display = moreMoviesVisible ? 'block' : 'none';

    // Optionally scroll to the section with visible results
    if (hasResults) {
      if (popularMoviesVisible) {
        popularMoviesSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else if (newMoviesVisible) {
        newMoviesSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else if (moreMoviesVisible) {
        moreMoviesSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }
  }
});
