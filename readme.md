# --- API

--- Add a brief description of the project here ---

## Features

- 🔐 **User Registration & Login** (JWT-based)  
- 🛡️ **Token Refresh and Revocation**  
- 🆔 **OAuth2 Integration** (e.g., Google login)  
- 📧 **Email Verification** via Gmail SMTP  
- 🔑 **Password Reset via Email**  
- 👤 **User Profile Endpoints**  
- 🧪 **Input Validation** using Pydantic v2  
- ⚙️ **FastAPI Dependency Injection & Scalable Design**  
- 📦 **Built with Poetry for environment and dependency management**  
- 🗄️ **Database Migrations with Alembic**

## Tech Stack

- **Framework**: FastAPI
- **Database**: POstgres
- **Authentication**: JWT / OAUTH2
- **Email**: Gmail SMTP
- **Validation**: Pydantic V2
- **Package Management**: Poetry

## Getting Started

### Prerequisites

- Python 3.8+
- Poetry package manager
- Docker (optional, for containerized setup)

### Installation

1. Clone the repository:

```bash
  git clone https://github.com/---
  cd ---
```

2. Create a `.env` file in the project root:

```bash
  cp .env.sample .env
```

Then edit the `.env` file with your specific configuration values.

---

## Environment Setup

### Using Poetry (Recommended)

1. Install Poetry if you haven't already:
```bash
  curl -sSL https://install.python-poetry.org | python3 - --version 1.8.2
```

2. Add Poetry to PATH:
```bash
  export PATH="$HOME/.local/bin:$PATH"
```

3. Verify Poetry installation:
```bash
  poetry --version
```

4. Create a virtual environment with Poetry:
```bash
  poetry env use python3.10  # or your preferred Python version
```

5. Install dependencies:
```bash
  poetry install
```

6. Activate the virtual environment:
```bash
  poetry shell
```

>  Alternatively, you can run commands within the virtual environment without activating it:
```bash
  poetry run <command>
```

### Using Standard Python venv

1. **Create a virtual environment**:  

```bash
  python3 -m venv .venv
```

2. **Activate the virtual environment**:  

- On macOS/Linux:  

```bash
  source .venv/bin/activate
```

- On Windows (PowerShell):  

```bash
  .venv\Scripts\Activate
```

3. **Install Poetry (if not already installed)**:

```bash
  pip install poetry
```

4. **Install project dependencies using Poetry**:  

```bash
  poetry install
```

---

## Running the Application

### Option 1: Using Docker (Recommended)

Build and start the containers:

```bash
  docker-compose up -d --build
```

### Option 2: (Using Poetry)

1. Activate the Poetry virtual environment (if not already activated):

```bash
  poetry shell
```

2. Run the application:

```bash
  uvicorn main:app --reload
```

The API will be available at `http://localhost:8000/`.

The API documentation will be available at http://localhost:8000/docs

---

## Project Structure

--- Add Project structure diagram here ---

---

## Development Tasks

### Adding Dependencies

```bash
  poetry add package-name
```

For development dependencies:

```bash
  poetry add --dev package-name
```

### Running Tests

```bash
  poetry run pytest
```

### Database Migrations

Initialize migrations **first time only**:

```bash
  alembic init alembic
```

Create a new migration **if you have made changes to the models**:

```bash
  alembic revision --autogenerate -m "migration message"
```

Apply migrations:

```bash
  alembic upgrade head
```

## License
![License](https://img.shields.io/badge/license-MIT-blue.svg)