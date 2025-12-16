# HTTP server in C
A lightweight HTTP server written in C, implementing RESTful APIs with SQLite for persistent storage and JSON request/response handling.

---

## Features Implemented So Far

- RESTful API endpoints for `STUDENTS` table:
  - **GET** `/students` → Retrieve all students
  - **GET** `/students/{id}` → Retrieve a student by ID
  - **POST** `/students` → Add a new student
  - **PUT** `/students/{id}` → Update a student completely
  - **PATCH** `/students/{id}` → Update student partially
  - **DELETE** `/students/{id}` → Remove a student__
- JSON-based communication between client and server
- SQLite3 integration for persistent storage
- Basic error handling (e.g., 404 for unknown resources)

---

## Project Structure

- `src/` → C source files (`.c`)  
- `include/` → Header files (`.h`)  
- `Makefile` → Build instructions  
- `README.md` → Project documentation  

---

## Build Instructions

Make sure you have `gcc`, `cJSON`, and `SQLite3` libraries installed.

```bash
make
```
## Run Instructions

```bash
./myServer
```
---
## Notes

- Use `make clean` to remove object files and the compiled binary
- Source files are in `src/`, headers in `include/`
- Current implementation supports basic CRUD operations for the `STUDENTS` table only
- Daily updates will be tracked in Git commits, reflecting new features or fixes

