# HTTP Server in C

A lightweight HTTP server written in C, implementing RESTful APIs with SQLite for persistent storage and JSON request/response handling. Currently, the project includes **user authentication via login and registration endpoints**.

---

## Features Implemented So Far

- RESTful API endpoints for testing purposes:
  - **GET** `/students` → Retrieve all students
  - **GET** `/students/{id}` → Retrieve a student by ID
  - **POST** `/students` → Add a new student
  - **PUT** `/students/{id}` → Update a student completely
  - **PATCH** `/students/{id}` → Update student partially
  - **DELETE** `/students/{id}` → Remove a student
- These endpoints were created for testing and demonstrating REST API functionality; the **main implementation focuses on user authentication**.

- **User Authentication Endpoints (Main Feature)**
  - **POST** `/register` → Register new users
  - **POST** `/login` → User login and JWT token generation
  - JWT-based authentication for secure session management:
    - Token includes standard claims (subject, issued time, expiration)
    - Token signed using a server-side secret
    - Expired tokens are rejected
  - Frontend pages included:
    - `login.html`
    - `registration.html`
    Both pages include embedded CSS and JS for form handling.
  - Forms are submitted via POST requests to ensure secure transmission of credentials.
  - Prevented insecure GET requests from browser form submission.

- JSON-based communication between client and server
- SQLite3 integration for persistent storage
- Basic error handling (e.g., 404 for unknown resources, 400 for invalid requests)

---

## Project Structure

- `src/` → C source files (`.c`)  
- `include/` → Header files (`.h`)  
- `public/` → HTML pages (`login.html`, `registration.html`)  
- `Makefile` → Build and run instructions  
- `README.md` → Project documentation  

---

## Dependencies

Make sure the following libraries are installed:

- gcc
- cJSON (`libcjson-dev`)
- SQLite3 (`libsqlite3-dev`)
- libjwt (`libjwt-dev`)
- OpenSSL (`libssl-dev`)

## Build Instructions

```bash
make

```
## Run Instructions

```bash
make run
```
---
## Notes

- Use `make clean` to remove object files and the compiled binary.
- Backend supports user login and registration with JWT authentication.
- Frontend HTML files (login.html and registration.html) contain all necessary CSS and JS; no separate app.js is required.
- The STUDENTS endpoints were created for testing REST API structure and are not part of the main implementation.
- JWT tokens ensure secure and stateless authentication for users.

