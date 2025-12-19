document.getElementById("loginForm").addEventListener("submit", function (e) {
    e.preventDefault();   // 🔥 STOP browser GET request

    const name = document.getElementById("name").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    fetch("/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            name,
            email,
            password
        })
    })
    .then(res => res.json())
    .then(data => {
        document.getElementById("msg").innerText = "Login successful";
        // store JWT here
    })
    .catch(err => {
        document.getElementById("msg").innerText = "Login failed";
    });
});
