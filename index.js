// Sidebar toggle functionality (unchanged)
let sidebar = document.querySelector(".sidebar");
let closeBtn = document.querySelector("#btn");
let searchBtn = document.querySelector(".bx-search");

closeBtn.addEventListener("click", () => {
  sidebar.classList.toggle("open");
  menuBtnChange();
});

searchBtn.addEventListener("click", () => {
  sidebar.classList.toggle("open");
  menuBtnChange();
});

function menuBtnChange() {
  if (sidebar.classList.contains("open")) {
    closeBtn.classList.replace("bx-menu", "bx-menu-alt-right");
  } else {
    closeBtn.classList.replace("bx-menu-alt-right", "bx-menu");
  }
}

  const addMovieBtn = document.getElementById('add-movie-btn');
  addMovieBtn.addEventListener('click', () => {
    const movieTitle = movieTitle.value;
    const movieImageFile = movieImageInput.files[0];
    const movieDescription = movieDescription.value;
    const selectedSection = sectionInput.value;

    if (!movieTitle || !movieImageFile || !movieDescription || !selectedSection) {
      alert("Please fill in all fields!");
      return;
    }

    const formData = new FormData();
    formData.append('title', movieTitle);
    formData.append('description', movieDescription);
    formData.append('section', selectedSection);
    formData.append('image', movieImageFile);

    fetch('add_movie.php', {
      method: 'POST',
      body: formData,
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        alert("Movie added successfully!");
      } else {
        alert("Error: " + data.message);
      }
    })
    .catch(error => {
      console.error('Error:', error);
    });
  });

//SLIDE SCROLL FUNCTIONALITY
function scrollSectionLeft(sectionClass) {
  const section = document.querySelector(`.${sectionClass}`);
  if (section) {
    section.scrollLeft -= 300; // scroll left by 200px
  } else {
    console.log(`Section with class ${sectionClass} not found`);
  }
}

function scrollSectionRight(sectionClass) {
  const section = document.querySelector(`.${sectionClass}`);
  if (section) {
    section.scrollLeft += 300; // scroll right by 200px
  } else {
    console.log(`Section with class ${sectionClass} not found`);
  }
}

window.onbeforeunload = function () {
  window.scrollTo(0, 0);
};
