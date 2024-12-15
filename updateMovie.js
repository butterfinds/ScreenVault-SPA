function openUpdateModal(movieId, title, description, trailerUrl) {
    console.log("Movie ID:", movieId);
    console.log("Title:", title);
    console.log("Description:", description);
    console.log("Trailer URL:", trailerUrl);

    document.getElementById('updateMovieId').value = movieId;
    document.getElementById('updateMovieTitle').value = title;
    document.getElementById('updateMovieDescription').value = description;
    document.getElementById('updateMovieTrailer').value = trailerUrl;
    const modal = document.getElementById('updateModal');
    modal.style.display = 'flex'; // Show modal
}
function closeUpdateModal() {
    const modal = document.getElementById('updateModal');
    modal.style.display = 'none'; // Hide modal
}