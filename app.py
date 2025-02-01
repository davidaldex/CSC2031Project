from config import app
from flask import render_template, abort

@app.route('/')
def index():
    return render_template('home/index.html')

# Error Handlers

# Handles 400 Bad Request errors
@app.errorhandler(400)
def bad_request_error(error):
    # Renders the 'error.html' template with error details and a 400 status code
    return render_template('errors/error.html',
                           error_code=400,
                           error_message="Bad Request",
                           error_description="The server could not understand the request due to invalid syntax."), 400

# Handles 404 Not Found errors
@app.errorhandler(404)
def not_found_error(error):
    # Renders the 'error.html' template with error details and a 404 status code
    return render_template('errors/error.html',
                           error_code=404,
                           error_message="Not Found",
                           error_description="The requested resource could not be found on this server."), 404

# Handles 500 Internal Server errors
@app.errorhandler(500)
def internal_server_error(error):
    # Renders the 'error.html' template with error details and a 500 status code
    return render_template('errors/error.html',
                           error_code=500,
                           error_message="Internal Server Error",
                           error_description="The server encountered an internal error and could not complete your request."), 500

# Handles 501 Not Implemented errors
@app.errorhandler(501)
def not_implemented_error(error):
    # Renders the 'error.html' template with error details and a 501 status code
    return render_template('errors/error.html',
                           error_code=501,
                           error_message="Not Implemented",
                           error_description="The server does not support the functionality required to fulfill the request."), 501

# Handles 429 Too Many Requests errors (rate-limiting)
@app.errorhandler(429)
def ratelimit_error(error):
    # Renders the 'error.html' template with error details and a 429 status code
    return render_template('errors/error.html',
                           error_code=429,
                           error_message="Too Many Requests",
                           error_description="You have made too many requests in a short period. Please try again later."), 429

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'))