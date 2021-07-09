from google_auth_oauthlib import flow as Flow
from googleapiclient.discovery import build

import logging
import wsgiref

_LOGGER = logging.getLogger(__name__)

class GoogleAuthService():
    """Implementation for Google OAuth 2.0"""

    def __init__(self):
        # Initializes the installed app flow.
        # Use the client_secret.json file to identify the application requesting
        # authorization. The client ID (from that file) and access scopes are required.
        self.flow = Flow.InstalledAppFlow.from_client_secrets_file(
            'client_secret.json',
            scopes=['https://www.googleapis.com/auth/userinfo.email', 'openid'])

    def auth_url(self, host = 'localhost', port = 8080):
        """Provides URL for authentication.

        Returns:
            string. URL for user authentication with google account.
        """

        self.flow.redirect_uri = "http://{}:{}/".format(host, port)
        return self.flow.authorization_url(prompt = 'consent')

    def get_credentials(self, auth_url, host = 'localhost', port = 8080):
        """Run the flow using the server strategy.

        The server strategy instructs the user to open the authorization URL in
        their browser and will attempt to automatically open the URL for them.
        It will start a local web server to listen for the authorization
        response. Once authorization is complete the authorization server will
        redirect the user's browser to the local web server. The web server
        will get the authorization code from the response and shutdown. The
        code is then exchanged for a token.

        Args:
            host (str): The hostname for the local redirect server. This will
                be served over http, not https.
            port (int): The port for the local redirect server.
            authorization_prompt_message (str): The message to display to tell
                the user to navigate to the authorization URL.
            success_message (str): The message to display in the web browser
                the authorization flow is complete.
            open_browser (bool): Whether or not to open the authorization URL
                in the user's browser.
            kwargs: Additional keyword arguments passed through to
                :meth:`authorization_url`.

        Returns:
            google.oauth2.credentials.Credentials: The OAuth 2.0 credentials
                for the user.
        """
        wsgi_app = _RedirectWSGIApp(self.flow._DEFAULT_WEB_SUCCESS_MESSAGE)
        local_server = wsgiref.simple_server.make_server(
            host, port, wsgi_app, handler_class = _WSGIRequestHandler
        )

        local_server.handle_request()

        # Note: using https here because oauthlib is very picky that
        # OAuth 2.0 should only occur over https.
        authorization_response = wsgi_app.last_request_uri.replace("http", "https")
        self.flow.fetch_token(authorization_response = authorization_response)

        return self.flow.credentials

    def validate_and_get_user_email(self, auth_url):
        """"Validates user and returns their email address.

        Returns:
            string: Authorized user's email address.
        """

        # Building oauth 2.0 service.
        oauth2 = build('oauth2', 'v2', credentials = self.get_credentials(auth_url))

        # Executing api request.
        user_info = oauth2.userinfo().get().execute()

        if user_info['verified_email'] == False:
            raise UserNotVerifiedException

        return user_info['email']

class UserNotVerifiedException(Exception):
    """Raised when user tries to validate using a non-verified google account.

    Attributes:
        expression -- input expression in which the error occurred.
        message -- explanation why exception is raised.
    """

    def __init__(self, expression, message):
        self.expression = expression
        self.message = 'The user\'s google account is not verified yet.'


class _WSGIRequestHandler(wsgiref.simple_server.WSGIRequestHandler):
    """Custom WSGIRequestHandler.

    Uses a named logger instead of printing to stderr.
    """

    def log_message(self, format, *args):
        # pylint: disable=redefined-builtin
        # (format is the argument name defined in the superclass.)
        _LOGGER.info(format, *args)


class _RedirectWSGIApp(object):
    """WSGI app to handle the authorization redirect.

    Stores the request URI and displays the given success message.
    """

    def __init__(self, success_message):
        """
        Args:
            success_message (str): The message to display in the web browser
                the authorization flow is complete.
        """
        self.last_request_uri = None
        self._success_message = success_message

    def __call__(self, environ, start_response):
        """WSGI Callable.

        Args:
            environ (Mapping[str, Any]): The WSGI environment.
            start_response (Callable[str, list]): The WSGI start_response
                callable.

        Returns:
            Iterable[bytes]: The response body.
        """

        start_response("200 OK", [("Content-type", "text/plain")])
        self.last_request_uri = wsgiref.util.request_uri(environ)
        return [self._success_message.encode("utf-8")]

if __name__ == '__main__':
    google_auth_service = GoogleAuthService()

    auth_url = google_auth_service.auth_url()[0]

    print(auth_url)
    print(google_auth_service.validate_and_get_user_email(auth_url))
