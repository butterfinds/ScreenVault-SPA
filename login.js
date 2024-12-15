// Form
const formOpenBtn = document.querySelector("#form-open"),
home = document.querySelector(".home"),
formContainer = document.querySelector(".form_container"),
formCloseBtn = document.querySelector(".form_close"),
signupBtn = document.querySelector("#signup"),
loginBtn = document.querySelector("#login"),
pwShowHide = document.querySelectorAll(".password");

//back button form
const backButton = document.querySelector(".back_button");

backButton.addEventListener("click", () => {
document.querySelector(".home").classList.remove("show");
});

formOpenBtn.addEventListener("click", () => home.classList.add("show"));
formCloseBtn.addEventListener("click", () => home.classList.remove("show"));


signupBtn.addEventListener("click", (e) => {
e.preventDefault();
formContainer.classList.add("active");
});

loginBtn.addEventListener("click", (e) => {
e.preventDefault();
formContainer.classList.remove("active");
});