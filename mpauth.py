"""This is a library that works with mod_python to allow you to use
a form-based login access control for any resource that Apache serves. See
README for more details.

If you have different resources that you are protecting with the same
Apache configuration, you can use a single login page with all of
them. To do this, you'll need to add a PythonOption action-path
directive to each of the protected resources that points to the OpenID
login handler.

For example, Alice has two directories, one "private" and one
"friends." She can set up one URL to handle login and then set
up each of the other directories separately::

<Directory "/var/www/friends">
    PythonOption action-path "/auth"
    PythonAccessHandler mpauth::protect
</Directory>

<Directory "/var/www/private">
    PythonOption action-path "/auth"
    PythonAccessHandler mpauth::protect
</Directory>

<Location "/auth">
    SetHandler mod_python
    PythonOption action-path "/auth"
    PythonOption hello-path "/auth/hello"
    PythonOption goodbye-path "/auth/goodbye"
    PythonHandler mpauth::login
</Location>

Session Keys
============

This module uses mod_python sessions. This is an overview of the data
that is stored in the session:

  `cookied_user` (OpenID identifier (unicode or str))

    If present, this is the currently logged in user. This is set
    upon successful login and cleared when logout is called.

  `target` (URL (str))

    The URL that the login code will redirect to once authentication
    has completed successfully. This is set by the `AccessHandler`
    (`protect`) and cleared when there is a successful login or
    replaced by another call to `protect`.

  `logout` (bool)

    Whether the last login action was a logout. This is used to know
    whether or not to attempt auto-login. When this key is present
    and true, auto-login is not attempted. Viewing the login page
    clears this flag.

  `message` (str)

    A key into the messages dictionary. The login page displays this
    message and clears this value. This is set whenever there is a
    message that needs to be displayed to the user.

Cookies
=======

This module sets a session cookie, as well as the following cookies:

  `mpauth.last_user` (user name (unicode or str))

    If present, this is an advisory cookie that indicates to the
    library.

"""

__copyright__ = """Copyright (C) 2005, 2006 JanRain, Inc."""

__license__ = """This is Free Software, under the terms of the GNU GPL.
See COPYING for details."""

__version__ = '1.2.0-pre4'

def free(apache_request):
    """Because there is no way to remove the PythonAccessHandler in
    a subdirectory, this handler will just pass the request.

    It should be used as a PythonAccessHandler. e.g.:

      PythonAccessHandler mpauth::free
    """
    return apache.OK

def protect(apache_request):
    """This is the function that protects a directory.

    It should be used as a PythonAccessHandler. e.g.:

      PythonAccessHandler mpauth::protect
      
    Options:
      action-path  root of auth path (defaults to /auth)
      allow-from   ip_address_or_network
    """

    login_req = LoginProtect(apache_request)
    try:
        return login_req.protect()
    finally:
        login_req.session.save()

def login(apache_request):
    """This is the function that handles OpenID logins

    It should be used as a PythonHandler. e.g.:

      SetHandler mod_python
      PythonHandler mpauth::login
      
    Options:
      action-path root of auth path (defaults to /auth)
      hello-path redirect here after login (defaults to /auth/hello)
      goodbye-path redirect here after logout (defaults to /auth/goodbye)
      
    """
    auth_req = AuthLogin(apache_request)
    try:
        return auth_req.dispatch()
    finally:
        auth_req.session.save()

##### The rest of this file is support for the functions above #####


import sys
import time
import os.path
import urllib
import urlparse
import ipaddr

from cgi import escape
from string import Template

try:
    from mod_python import apache, util, Cookie, Session
except ImportError:
    print >>sys.stderr, ("Unable to import mod_python code. Continuing "
                         "anyway (for pychecker)")
    sys.stderr.flush()
    apache = util = Cookie = Session = None
    
cookie_version = 'v1'

message_text = {
    'empty':('message',  'Enter a user name and password to continue'),
    'cancel':('message', 'Authorization cancelled'),
    'http_failed':('error',
                   'There was an error communicating with the server'),
    'failure':('error', 'The server reported an error'),
    'denied':('error',  'Acess to this resource is denied'),
    }
    
hello_page_tmpl = '''\
<html>
  <head>
    <title>$title</title>
    <style type="text/css">
      body {
          margin: 5px 15px 0px 15px;
          font-family:arial,sans-serif;
          background-color: #ffffff;
          font-size: 80%;
      }
     </style>
  </head>
  <body><h1>Welcome</h1>
  <p>You are now logged in.</p>
  <p><a href="$logout">Log out</a></p>
  </body>
</html>
'''

goodbye_page_tmpl = '''\
<html>
  <head>
    <title>$title</title>
    <style type="text/css">
      body {
          margin: 5px 15px 0px 15px;
          font-family:arial,sans-serif;
          background-color: #ffffff;
          font-size: 80%;
      }
     </style>
  </head>
  <body><h1>Goodbye</h1>
  <p>You are now logged out.</p>
  <p><a href="$login">Log in</a></p>
  </body>
</html>
'''

login_page_tmpl = '''\
<html>
  <head>
    <title>$title</title>
    <style type="text/css">
      body {
          margin: 5px 15px 0px 15px;
          font-family:arial,sans-serif;
          background-color: #ffffff;
          font-size: 80%;
      }
      .form-noindent {
        cell-padding:1px;
        background-color: #ddf8cc;
        border: #80c65a 1px solid;
      }
      div.error {
          background: #ffdddd;
          border: 1px solid red;
          padding: 0.5em;
      }
      div.message {
          background: #ffffdd;
          border: 1px solid yellow;
          padding: 0.5em;
      }
    </style>
  </head>
  <body onLoad="document.login_form.login.focus();">
    <h1>$title</h1>$resource $message
<form method="post" action="$action" name="login_form">
  <table class="form-noindent" cellspacing="3" cellpadding="5" border="0">
    <tr>
      <td valign="top" style="text-align:center" nowrap="nowrap" bgcolor="ddf8cc">
        <table align="center" border="0" cellpadding="1" cellspacing="0">
          <tr><td colspan="2">Enter your user name and password to continue.</td></tr>
          <tr><td align="right"><label for="login">User name:</label></td>
            <td><input type="text" name="login" value="$login" /></td></tr>
          <tr><td align="right"><label for="password">Password:</label></td>
            <td><input type="password" name="password" value="" /></td></tr>
          <tr><td>&nbsp;</td>
            <td><input type="submit" value="Continue" /></td></tr>
        </table></td>
     </tr>
  </table>
</form>
</body>
</html>
'''

class LoginAccessRequest(object):
    # Cache for store instances
    _file_stores = {}
    _max_store_cache_size = 5

    # Cache for authorized identities
    _authorized_cache = {}
    _max_authorized_cache_size = 100

    # Time out sessions after a week of no access
    session_timeout = 60 * 60 * 24 * 7

    def __init__(self, apache_request):
        self.apache_request = apache_request
        self.options = apache_request.get_options()
        self.session = Session.Session(
            apache_request,
            timeout=self.session_timeout,
            lock=False)

    def get_cookied_user(self):
        """Get the user cookie for this request

        mod_python.Request -> NoneType or str
        """
        return self.session.get('cookied_user')

    def set_cookied_user(self, username):
        """Set the user cookie for this user

        (mod_python.Request, str, int) -> NoneType
        """
        self.session['cookied_user'] = username

    cookied_user = property(get_cookied_user, set_cookied_user)

    def getServerURL(self):
        """Return a URL to the root of the server that is serving this
        request.

        mod_python.Request -> str
        """
        host = self.apache_request.hostname
        port = self.apache_request.connection.local_addr[1]

        # Don't include the default port number in the URL
        if self.apache_request.subprocess_env.get('HTTPS', 'off') == 'on':
            default_port = 443
            proto = 'https'
        else:
            default_port = 80
            proto = 'http'

        if port == default_port:
            server_url = '%s://%s/' % (proto, host)
        else:
            server_url = '%s://%s:%s/' % (proto, host, port)

        return server_url

    def getActionPath(self):
        raise NotImplementedError

    def getTargetPath(self, key='hello'):
        """Find the URL to go to after login or logout
        """
        target_path = self.options.get('%s-path' % key)
        if target_path is None:
            target_path = self.getActionPath() + key
        return target_path

    def loginRedirect(self, message=None, target=None, logout=False):
        """Issue a 302 redirect to the login page.

        (mod_python.Request, str or NoneType, str or NoneType) ->
            apache.SERVER_RETURN"""
        if target:
            self.session['target'] = target
        self.session['message'] = message
        self.session['logout'] = logout
        location = None
        if logout:
            location = self.targetURL('goodbye')
        else:
            location = self.actionURL('login')
        self.redirect(location)

    def redirect(self, url):
        # This function raises an exception, so it will halt anything
        # that calls it. This is probably what you want, but beware!
        util.redirect(self.apache_request, url)

    def actionURL(self, action):
        """Generate a URL that performs the given action. This depends
        on knowing where the actions live.
        """
        return urlparse.urljoin(self.getServerURL(), self.getActionPath() + action)
        
    def targetURL(self, key='hello'):
        """Generate a URL that performs the given action. This depends
        on knowing where the actions live.
        """
        return urlparse.urljoin(self.getServerURL(), self.getTargetPath(key))

class AuthLogin(LoginAccessRequest):

    # How long to keep the last_user cookie that is used to automate
    # login
    auto_login_lifetime = 24 * 60 * 60 * 365
    
    def getLastUser(self):
        cookies = Cookie.get_cookies(self.apache_request)
        cookie = cookies.get('mpauth.last_user')
        if cookie is None:
            return None
        words = cookie.value.rsplit('~~', 1)
        user = words[0]
        version = None
        if len(words) == 2:
            version = words[1]
        if version != cookie_version or not user:
            return None
        return user

    def setLastUser(self, username):
        assert isinstance(username, basestring)
        expires = time.time() + self.auto_login_lifetime
        value = '%s~~%s' % (username, cookie_version) 
        Cookie.add_cookie(self.apache_request,
            'mpauth.last_user', value, path='/', expires=expires)
        self.apache_request.log_error('Set last user: %s' % value)

    def delLastUser(self):
        Cookie.add_cookie(
            self.apache_request, 'mpauth.last_user', '', path='/', expires=0)
        self.apache_request.log_error('Deleted last user')

    def fillLoginPage(self, login, messages):
        """Generate the HTML for the login page
        """
        message_chunks = []
        for name in messages:
            message_info = message_text.get(name)
            if message_info is None:
                message_info = ('error', 'An error occurred')

            chunk = "<div class='%s'>%s</div>" % message_info
            message_chunks.append(chunk)

        if self.cookied_user:
            chunk = ("<div class='message'>You are currently logged "
                     "in as %s. (<a href='%s'>logout</a>)</div>"
                     % (escape(self.cookied_user),
                        escape(self.actionURL('logout'), True)))
            message_chunks.append(chunk)

        message_html = '\n'.join(message_chunks)

        target = self.session.get('target')
        if target:
            resource = (
                '<div class="message">Authorization is required to access '
                '<code>%s</code></div>') % (escape(target),)
        else:
            resource = ''

        if not login:
            login = ''
        return Template(login_page_tmpl).substitute(
            action=escape(self.actionURL('login'), True),
            resource=resource,
            title='Kentfield School District',
            message=message_html,
            login=escape(login, True),
            )

    def getActionPath(self):
        """Find the URL to the actions
        """
        # First check configuration
        action_path = self.options.get('action-path')
        if action_path is None:
            # Default to path for this request (since this handler *is*
            # the action path)
            #
            # Too bad there is no way to just get the Apache path to
            # this handler. It depends on whether this handler appears
            # in a <Files>, <Directory>, or <Location> section. (see
            # <http://mail-archives.apache.org/mod_mbox/httpd-python-dev/200610.mbox/%3C15703531.1161216215467.JavaMail.jira@brutus%3E>)
            path_info = self.apache_request.path_info
            if path_info:
                assert self.apache_request.uri.endswith(path_info)
                action_path = self.apache_request.uri[:-len(path_info)]
            else:
                action_path = self.apache_request.uri

            # XXX: if this is '/' or '' there is probably something
            # wrong with the config because it'd be pretty silly to
            # have this handler at the root of a server. We should
            # tell the user, but how?

        # Make sure that there is a trailing slash on the action path
        if not action_path or action_path[-1] != '/':
            action_path += '/'

        return action_path
        
    def dispatch(self):
        """Dispatch to the appropriate access control action.
        """
        action_path = self.getActionPath()
        if self.apache_request.uri.startswith(action_path):
            action = self.apache_request.uri[len(action_path):]
        else:
            self.apache_request.log_error(
                'Action path does not match my URL. Configuration problem? '
                '(action_path=%r, uri=%r)' %
                (action_path, self.apache_request.uri))
            self.loginRedirect()

        try:
            handler = getattr(self, 'do_' + action)
        except AttributeError:
            # An action we don't know about was called.
            self.apache_request.log_error(
                "Unknown access control action: %r" % (action,))
            self.loginRedirect()
        else:
            return handler()

    def do_logout(self):
        self.delLastUser()
        try:
            del self.session['cookied_user']
        except KeyError:
            pass
        self.loginRedirect(logout=True)

    def do_login(self):
        """Show a login page for setting the user cookie.
        """
        form = None
        login = None
        password = None
        immediate = False

        if self.apache_request.method == 'POST':
            form = util.FieldStorage(self.apache_request)
            login = form.getfirst('login', self.cookied_user)
            password = form.getfirst('password', None)
        
        if self.session.get('logout'):
            del self.session['logout']
        else:
          last_user = self.getLastUser()
          if not login and bool(last_user):
              login = last_user
              password = 'by-cookie'
              immediate = True

        message = self.session.get('message', None)
        if message is None:
            messages = []
        else:
            messages = [message]

        if self.apache_request.method == 'POST' or immediate:
            if login:
                self.authenticate_login(login, password)
            else:
                messages.append('empty')

        text = self.fillLoginPage(login, messages)
        self.apache_request.content_type = 'text/html; charset=UTF-8'
        self.apache_request.set_content_length(len(text))
        self.apache_request.write(text)
        self.session['message'] = None
        return apache.OK

    def is_authentic(self, login, password):
        """Logic for authenticating user goes here.
        Replace this stub with database or ldap lookup
        return True or False
        """
        
        return True
    end

    def authenticate_login(self, login, password):
        """Handle a response from the login form. Always redirects.
        mod_python.Request -> apache.SERVER_RETURN
        """
            
        # Process form data and get response from database
        response = None
        if login is not None and password is not None and self.is_authentic(login, password):
            response = 'SUCCESS' 
        if response is None:
            self.loginRedirect(message='failure')
        elif response == 'SUCCESS':
            # Set the cookie and then redirect back to the target
            self.cookied_user = login
            self.setLastUser(login)
            target = self.session.get('target')
            if not target:
                target = self.targetURL('hello')
            self.session['target'] = None
            self.redirect(target)
        elif response == 'CANCEL':
            self.loginRedirect(message='cancel')
        elif response == 'FAILURE':
            self.loginRedirect(message='failure')
        else:
            assert False, response
            
    def do_hello(self):
        """Default page if none specified"""
        text = Template(hello_page_tmpl).substitute(
            logout=escape(self.actionURL('logout'), True),
            title='Kentfield School District',
            )
        self.apache_request.content_type = 'text/html; charset=UTF-8'
        self.apache_request.set_content_length(len(text))
        self.apache_request.write(text)
        self.session['message'] = None
        return apache.OK

    def do_goodbye(self):
        """Default page if none specified"""
        """Default page if none specified"""
        text = Template(goodbye_page_tmpl).substitute(
            login=escape(self.actionURL('login'), True),
            title='Kentfield School District',
            )
        self.apache_request.content_type = 'text/html; charset=UTF-8'
        self.apache_request.set_content_length(len(text))
        self.apache_request.write(text)
        self.session['message'] = None
        return apache.OK

class LoginProtect(LoginAccessRequest):
    def getActionPath(self):
        """Find the URL to the actions
        """
        action_path = self.options.get('action-path')
        if action_path is None:
            # the path where *Handler directive was specified
            protected_path = self.apache_request.hlist.directory
            if protected_path:
                docroot = self.apache_request.document_root()
                protected_path = protected_path[len(docroot):]
                if not protected_path or protected_path[-1] != '/':
                    protected_path += '/'
            else:
                self.apache_request.log_error(
                    'No action-path specified and the protect directive is '
                    'in a <Location> block. Defaulting to /auth for login '
                    'actions.')

                protected_path = '/'
            action_path = protected_path + 'auth/'
                
        elif not action_path or action_path[-1] != '/':
                action_path += '/'

        return action_path

    def protect(self):
        """Only allow the request to proceed if the user
        has authenticated.

        mod_python.Request -> int or apache.SERVER_RETURN
        """
        # Do not apply rule if client ip is in allow-from network
        allow_from = self.options.get('allow-from')
        if allow_from is not None:
            remote_host = self.apache_request.get_remote_host(apache.REMOTE_NOLOOKUP)
            for ip_string in allow_from.split():
                allow_net = ipaddr.IP(ip_string)
                if ipaddr.IP(remote_host) in allow_net:
                    # self.apache_request.log_error('OK: remote_host %r in %r' % (remote_host, ip_string))
                    return apache.OK

        # Do not apply rule if this is handled by one of the authentication
        # access control actions.
        action_path = self.getActionPath()
        if self.apache_request.uri.startswith(action_path):
            return apache.OK

        request_uri = urlparse.urljoin(
            self.getServerURL(), self.apache_request.uri)

        if self.cookied_user:
            # Check to see if cookied user is authorized
            if True:
                self.apache_request.user = self.cookied_user

                # Do not cache this access-controlled page
                self.apache_request.headers_out['Cache-Control'] = 'no-cache'

                return apache.OK
            else:
                self.apache_request.log_error(
                    'Unauthorized access attempt from %r for %r' %
                    (self.cookied_user, request_uri))
                message = 'denied'
        else:
            # Initial request with no openid_identifier cookie, so no message.
            message = None

        # The redirects only work for GET, so just return FORBIDDEN if
        # it's any other method.
        if self.apache_request.method != 'GET':
            raise apache.SERVER_RETURN, apache.HTTP_FORBIDDEN

        # cookied_user not authorized or not set, so redirect to login
        self.loginRedirect(message, request_uri)
