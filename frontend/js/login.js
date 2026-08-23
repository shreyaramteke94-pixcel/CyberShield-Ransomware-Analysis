const loginForm = document.getElementById("loginForm");

loginForm.addEventListener("submit", function (event) {

    event.preventDefault();

    const email =
        document.getElementById("email").value.trim();

    const password =
        document.getElementById("password").value.trim();


    if (!email || !password) {

        alert("Please enter your email and password.");

        return;
    }


    /*
        Frontend demonstration only.

        A real website should authenticate
        the user through a secure backend.
    */

    sessionStorage.setItem(
        "cyberShieldLoggedIn",
        "true"
    );

    sessionStorage.setItem(
        "cyberShieldUser",
        email
    );


    window.location.href = "dashboard.html";

});