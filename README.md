
# FastAPI Authentication and User Management

Welcome to the **FastAPI Authentication and User Management** project! This repository contains a template for managing user authentication, registration, and authorization using FastAPI, an efficient and easy-to-use Python web framework.

## Features

- **User Registration**: Allow new users to register with a username, email, and password.
- **User Login**: Authenticate users using JWT tokens.
- **Password Hashing**: Secure passwords using bcrypt hashing.
- **Token-Based Authentication**: Secure API routes using JWT (JSON Web Tokens).
- **User Management**: Retrieve, update, and delete user details.
- **Role-Based Access Control (RBAC)**: Manage access to resources based on user roles.
- **API Documentation**: Automatic generation of API docs with Swagger UI and ReDoc.

## Getting Started

### Prerequisites

- **Python 3.7+** installed on your machine.
- **pip**: Python package manager.
- **virtualenv** (optional but recommended) for creating a virtual environment.

### Installation

1. **Clone the repository**:

    ```bash
    git clone https://github.com/janardan-ds/login.git
    cd login
    ```

2. **Create and activate a virtual environment**:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install the dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

4. **Run the application**:

    ```bash
    uvicorn main:app --reload
    ```

    This will start the FastAPI server, and you can view the API documentation at `http://127.0.0.1:8000/docs` or `http://127.0.0.1:8000/redoc`.

## Project Structure

```plaintext
login/
├── app/
│   ├── __init__.py
│   ├── main.py             # Entry point of the application
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── dependencies.py # JWT authentication and authorization logic
│   │   └── utils.py        # Utilities for hashing and verifying passwords
│   ├── models/
│   │   └── user.py         # User models for ORM
│   ├── routers/
│   │   └── user.py         # User-related routes (registration, login, etc.)
│   └── schemas/
│       └── user.py         # Pydantic schemas for request/response validation
├── tests/                  # Test cases for the application
│   └── test_auth.py
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```

## Usage

1. **Register a new user**: Send a `POST` request to `/register` with JSON payload `{ "username": "your_username", "password": "your_password" }`.

2. **Login**: Send a `POST` request to `/login` to obtain a JWT token.

3. **Access Protected Routes**: Use the JWT token in the `Authorization` header as `Bearer <token>` to access protected routes.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or bug fixes.

## Acknowledgements

- [FastAPI](https://fastapi.tiangolo.com/)
- [bcrypt](https://pypi.org/project/bcrypt/)
- [JWT](https://jwt.io/)
