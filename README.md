# Qi Xing Forums

A modern forum application built with Flask and JavaScript.

## Features

- User authentication (signup/login)
- Create and view forum threads
- Post replies with file attachments
- Admin capabilities
- Responsive design

## Setup

1. Clone the repository
2. Install Python dependencies:
   ```bash
   pip install flask flask-cors flask-sqlalchemy werkzeug
   ```
3. Run the Flask backend:
   ```bash
   python app.py
   ```
4. Open `index.html` in your browser

## Development

- Backend: Flask with SQLite database
- Frontend: HTML, CSS, JavaScript
- File uploads supported
- CORS enabled for local development

## Security Notes

This is a development version. For production:
- Use proper session management
- Implement secure file uploads
- Use environment variables for sensitive data
- Enable HTTPS
- Use a production-grade WSGI server 