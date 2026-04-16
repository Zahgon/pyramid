import base64
import binascii
from codecs import utf_8_decode, utf_8_encode
from collections import namedtuple
import hashlib
import re
import time as time_mod
from urllib.parse import quote, unquote
import warnings
from webob.cookies import CookieProfile
from zope.interface import implementer

from pyramid.authorization import Authenticated, Everyone
from pyramid.interfaces import IAuthenticationPolicy, IDebugLogger
from pyramid.util import (
    SimpleSerializer,
    ascii_,
    bytes_,
    strings_differ,
    text_,
)

VALID_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9+_-]*$")


class CallbackAuthenticationPolicy:
    """Abstract class"""

    debug = False
    callback = None

    def _log(self, msg, methodname, request):
        pass

    def _clean_principal(self, princid):
        pass

    def authenticated_userid(self, request):
        """Return the authenticated userid or ``None``.

        If no callback is registered, this will be the same as
        ``unauthenticated_userid``.

        If a ``callback`` is registered, this will return the userid if
        and only if the callback returns a value that is not ``None``.

        """
        pass

    def effective_principals(self, request):
        """A list of effective principals derived from request.

        This will return a list of principals including, at least,
        :data:`pyramid.authorization.Everyone`. If there is no authenticated
        userid, or the ``callback`` returns ``None``, this will be the
        only principal:

        .. code-block:: python

            return [Everyone]

        If the ``callback`` does not return ``None`` and an authenticated
        userid is found, then the principals will include
        :data:`pyramid.authorization.Authenticated`, the
        ``authenticated_userid`` and the list of principals returned by the
        ``callback``:

        .. code-block:: python

            extra_principals = callback(userid, request)
            return [Everyone, Authenticated, userid] + extra_principals

        """
        pass


@implementer(IAuthenticationPolicy)
class RepozeWho1AuthenticationPolicy(CallbackAuthenticationPolicy):
    """A :app:`Pyramid` :term:`authentication policy` which
    obtains data from the :mod:`repoze.who` 1.X WSGI 'API' (the
    ``repoze.who.identity`` key in the WSGI environment).

    Constructor Arguments

    ``identifier_name``

       Default: ``auth_tkt``.  The :mod:`repoze.who` plugin name that
       performs remember/forget.  Optional.

    ``callback``

        Default: ``None``.  A callback passed the :mod:`repoze.who` identity
        and the :term:`request`, expected to return ``None`` if the user
        represented by the identity doesn't exist or a sequence of principal
        identifiers (possibly empty) representing groups if the user does
        exist.  If ``callback`` is None, the userid will be assumed to exist
        with no group principals.

    Objects of this class implement the interface described by
    :class:`pyramid.interfaces.IAuthenticationPolicy`.
    """

    def __init__(self, identifier_name='auth_tkt', callback=None):
        self.identifier_name = identifier_name
        self.callback = callback

    def _get_identity(self, request):
        pass

    def _get_identifier(self, request):
        pass

    def authenticated_userid(self, request):
        """Return the authenticated userid or ``None``.

        If no callback is registered, this will be the same as
        ``unauthenticated_userid``.

        If a ``callback`` is registered, this will return the userid if
        and only if the callback returns a value that is not ``None``.

        """
        pass

    def unauthenticated_userid(self, request):
        """Return the ``repoze.who.userid`` key from the detected identity."""
        pass

    def effective_principals(self, request):
        """A list of effective principals derived from the identity.

        This will return a list of principals including, at least,
        :data:`pyramid.authorization.Everyone`. If there is no identity, or
        the ``callback`` returns ``None``, this will be the only principal.

        If the ``callback`` does not return ``None`` and an identity is
        found, then the principals will include
        :data:`pyramid.authorization.Authenticated`, the
        ``authenticated_userid`` and the list of principals returned by the
        ``callback``.

        """
        pass

    def remember(self, request, userid, **kw):
        """Store the ``userid`` as ``repoze.who.userid``.

        The identity to authenticated to :mod:`repoze.who`
        will contain the given userid as ``userid``, and
        provide all keyword arguments as additional identity
        keys. Useful keys could be ``max_age`` or ``userdata``.
        """
        pass

    def forget(self, request):
        """Forget the current authenticated user.

        Return headers that, if included in a response, will delete the
        cookie responsible for tracking the current user.

        """
        pass


@implementer(IAuthenticationPolicy)
class RemoteUserAuthenticationPolicy(CallbackAuthenticationPolicy):
    """A :app:`Pyramid` :term:`authentication policy` which
    obtains data from the ``REMOTE_USER`` WSGI environment variable.

    Constructor Arguments

    ``environ_key``

        Default: ``REMOTE_USER``.  The key in the WSGI environ which
        provides the userid.

    ``callback``

        Default: ``None``.  A callback passed the userid and the request,
        expected to return None if the userid doesn't exist or a sequence of
        principal identifiers (possibly empty) representing groups if the
        user does exist.  If ``callback`` is None, the userid will be assumed
        to exist with no group principals.

    ``debug``

        Default: ``False``.  If ``debug`` is ``True``, log messages to the
        Pyramid debug logger about the results of various authentication
        steps.  The output from debugging is useful for reporting to maillist
        or IRC channels when asking for support.

    Objects of this class implement the interface described by
    :class:`pyramid.interfaces.IAuthenticationPolicy`.
    """

    def __init__(self, environ_key='REMOTE_USER', callback=None, debug=False):
        self.environ_key = environ_key
        self.callback = callback
        self.debug = debug

    def unauthenticated_userid(self, request):
        """The ``REMOTE_USER`` value found within the ``environ``."""
        pass

    def remember(self, request, userid, **kw):
        """A no-op. The ``REMOTE_USER`` does not provide a protocol for
        remembering the user. This will be application-specific and can
        be done somewhere else or in a subclass."""
        pass

    def forget(self, request):
        """A no-op. The ``REMOTE_USER`` does not provide a protocol for
        forgetting the user. This will be application-specific and can
        be done somewhere else or in a subclass."""
        pass


@implementer(IAuthenticationPolicy)
class AuthTktAuthenticationPolicy(CallbackAuthenticationPolicy):
    """A :app:`Pyramid` :term:`authentication policy` which
    obtains data from a Pyramid "auth ticket" cookie.

    Constructor Arguments

    ``secret``

       The secret (a string) used for auth_tkt cookie signing.  This value
       should be unique across all values provided to Pyramid for various
       subsystem secrets (see :ref:`admonishment_against_secret_sharing`).
       Required.

    ``callback``

       Default: ``None``.  A callback passed the userid and the
       request, expected to return ``None`` if the userid doesn't
       exist or a sequence of principal identifiers (possibly empty) if
       the user does exist.  If ``callback`` is ``None``, the userid
       will be assumed to exist with no principals.  Optional.

    ``cookie_name``

       Default: ``auth_tkt``.  The cookie name used
       (string).  Optional.

    ``secure``

       Default: ``False``.  Only send the cookie back over a secure
       conn.  Optional.

    ``include_ip``

       Default: ``False``.  Make the requesting IP address part of
       the authentication data in the cookie.  Optional.

       For IPv6 this option is not recommended. The ``mod_auth_tkt``
       specification does not specify how to handle IPv6 addresses, so using
       this option in combination with IPv6 addresses may cause an
       incompatible cookie. It ties the authentication ticket to that
       individual's IPv6 address.

    ``timeout``

       Default: ``None``.  Maximum number of seconds which a newly
       issued ticket will be considered valid.  After this amount of
       time, the ticket will expire (effectively logging the user
       out).  If this value is ``None``, the ticket never expires.
       Optional.

    ``reissue_time``

       Default: ``None``.  If this parameter is set, it represents the number
       of seconds that must pass before an authentication token cookie is
       automatically reissued as the result of a request which requires
       authentication.  The duration is measured as the number of seconds
       since the last auth_tkt cookie was issued and 'now'.  If this value is
       ``0``, a new ticket cookie will be reissued on every request which
       requires authentication.

       A good rule of thumb: if you want auto-expired cookies based on
       inactivity: set the ``timeout`` value to 1200 (20 mins) and set the
       ``reissue_time`` value to perhaps a tenth of the ``timeout`` value
       (120 or 2 mins).  It's nonsensical to set the ``timeout`` value lower
       than the ``reissue_time`` value, as the ticket will never be reissued
       if so.  However, such a configuration is not explicitly prevented.

       Optional.

    ``max_age``

       Default: ``None``.  The max age of the auth_tkt cookie, in
       seconds.  This differs from ``timeout`` inasmuch as ``timeout``
       represents the lifetime of the ticket contained in the cookie,
       while this value represents the lifetime of the cookie itself.
       When this value is set, the cookie's ``Max-Age`` and
       ``Expires`` settings will be set, allowing the auth_tkt cookie
       to last between browser sessions.  It is typically nonsensical
       to set this to a value that is lower than ``timeout`` or
       ``reissue_time``, although it is not explicitly prevented.
       Optional.

    ``path``

       Default: ``/``. The path for which the auth_tkt cookie is valid.
       May be desirable if the application only serves part of a domain.
       Optional.

    ``http_only``

       Default: ``False``. Hide cookie from JavaScript by setting the
       HttpOnly flag. Not honored by all browsers.
       Optional.

    ``wild_domain``

       Default: ``True``. An auth_tkt cookie will be generated for the
       wildcard domain. If your site is hosted as ``example.com`` this
       will make the cookie available for sites underneath ``example.com``
       such as ``www.example.com``.
       Optional.

    ``parent_domain``

       Default: ``False``. An auth_tkt cookie will be generated for the
       parent domain of the current site. For example if your site is
       hosted under ``www.example.com`` a cookie will be generated for
       ``.example.com``. This can be useful if you have multiple sites
       sharing the same domain. This option supercedes the ``wild_domain``
       option.
       Optional.

    ``domain``

       Default: ``None``. If provided the auth_tkt cookie will only be
       set for this domain. This option is not compatible with ``wild_domain``
       and ``parent_domain``.
       Optional.

    ``hashalg``

       Default: ``sha512`` (the literal string).

       Any hash algorithm supported by Python's ``hashlib.new()`` function
       can be used as the ``hashalg``.

       Cookies generated by different instances of AuthTktAuthenticationPolicy
       using different ``hashalg`` options are not compatible. Switching the
       ``hashalg`` will imply that all existing users with a valid cookie will
       be required to re-login.

       Optional.

    ``debug``

        Default: ``False``.  If ``debug`` is ``True``, log messages to the
        Pyramid debug logger about the results of various authentication
        steps.  The output from debugging is useful for reporting to maillist
        or IRC channels when asking for support.

    ``samesite``

        Default: ``'Lax'``.  The 'samesite' option of the session cookie. Set
        the value to the string ``'None'`` to turn off the samesite option.

    .. versionchanged:: 1.4

       Added the ``hashalg`` option, defaulting to ``sha512``.

    .. versionchanged:: 1.5

       Added the ``domain`` option.

       Added the ``parent_domain`` option.

    .. versionchanged:: 1.10

       Added the ``samesite`` option and made the default ``'Lax'``.

    Objects of this class implement the interface described by
    :class:`pyramid.interfaces.IAuthenticationPolicy`.

    """

    def __init__(
        self,
        secret,
        callback=None,
        cookie_name='auth_tkt',
        secure=False,
        include_ip=False,
        timeout=None,
        reissue_time=None,
        max_age=None,
        path="/",
        http_only=False,
        wild_domain=True,
        debug=False,
        hashalg='sha512',
        parent_domain=False,
        domain=None,
        samesite='Lax',
    ):
        self.cookie = AuthTktCookieHelper(
            secret,
            cookie_name=cookie_name,
            secure=secure,
            include_ip=include_ip,
            timeout=timeout,
            reissue_time=reissue_time,
            max_age=max_age,
            http_only=http_only,
            path=path,
            wild_domain=wild_domain,
            hashalg=hashalg,
            parent_domain=parent_domain,
            domain=domain,
            samesite=samesite,
        )
        self.callback = callback
        self.debug = debug

    def unauthenticated_userid(self, request):
        """The userid key within the auth_tkt cookie."""
        pass

    def remember(self, request, userid, **kw):
        """Accepts the following kw args: ``max_age=<int-seconds>,
        ``tokens=<sequence-of-ascii-strings>``.

        Return a list of headers which will set appropriate cookies on
        the response.

        """
        pass

    def forget(self, request):
        """A list of headers which will delete appropriate cookies."""
        pass


def b64encode(v):
    return base64.b64encode(bytes_(v)).strip().replace(b'\n', b'')


def b64decode(v):
    return base64.b64decode(bytes_(v))


# this class licensed under the MIT license (stolen from Paste)
class AuthTicket:
    """
    This class represents an authentication token.  You must pass in
    the shared secret, the userid, and the IP address.  Optionally you
    can include tokens (a list of strings, representing role names),
    'user_data', which is arbitrary data available for your own use in
    later scripts.  Lastly, you can override the cookie name and
    timestamp.

    Once you provide all the arguments, use .cookie_value() to
    generate the appropriate authentication ticket.

    Usage::

        token = AuthTicket('sharedsecret', 'username',
            os.environ['REMOTE_ADDR'], tokens=['admin'])
        val = token.cookie_value()

    """

    def __init__(
        self,
        secret,
        userid,
        ip,
        tokens=(),
        user_data='',
        time=None,
        cookie_name='auth_tkt',
        secure=False,
        hashalg='md5',
    ):
        self.secret = secret
        self.userid = userid
        self.ip = ip
        self.tokens = ','.join(tokens)
        self.user_data = user_data
        if time is None:
            self.time = time_mod.time()
        else:
            self.time = time
        self.cookie_name = cookie_name
        self.secure = secure
        self.hashalg = hashalg

    def digest(self):
        pass

    def cookie_value(self):
        pass


# this class licensed under the MIT license (stolen from Paste)
class BadTicket(Exception):
    """
    Exception raised when a ticket can't be parsed.  If we get far enough to
    determine what the expected digest should have been, expected is set.
    This should not be shown by default, but can be useful for debugging.
    """

    def __init__(self, msg, expected=None):
        self.expected = expected
        Exception.__init__(self, msg)


# this function licensed under the MIT license (stolen from Paste)
def parse_ticket(secret, ticket, ip, hashalg='md5'):
    """
    Parse the ticket, returning (timestamp, userid, tokens, user_data).

    If the ticket cannot be parsed, a ``BadTicket`` exception will be raised
    with an explanation.
    """
    pass


# this function licensed under the MIT license (stolen from Paste)
def calculate_digest(
    ip, timestamp, secret, userid, tokens, user_data, hashalg='md5'
):
    pass


# this function licensed under the MIT license (stolen from Paste)
def encode_ip_timestamp(ip, timestamp):
    pass


class AuthTktCookieHelper:
    """
    A helper class for security policies that obtains data from an "auth
    ticket" cookie.

    Constructor Arguments

    ``secret``

       The secret (a string) used for auth_tkt cookie signing.  This value
       should be unique across all values provided to Pyramid for various
       subsystem secrets (see :ref:`admonishment_against_secret_sharing`).
       Required.

    ``cookie_name``

       Default: ``auth_tkt``.  The cookie name used
       (string).  Optional.

    ``secure``

       Default: ``False``.  Only send the cookie back over a secure
       conn.  Optional.

    ``include_ip``

       Default: ``False``.  Make the requesting IP address part of
       the authentication data in the cookie.  Optional.

       For IPv6 this option is not recommended. The ``mod_auth_tkt``
       specification does not specify how to handle IPv6 addresses, so using
       this option in combination with IPv6 addresses may cause an
       incompatible cookie. It ties the authentication ticket to that
       individual's IPv6 address.

    ``timeout``

       Default: ``None``.  Maximum number of seconds which a newly
       issued ticket will be considered valid.  After this amount of
       time, the ticket will expire (effectively logging the user
       out).  If this value is ``None``, the ticket never expires.
       Optional.

    ``reissue_time``

       Default: ``None``.  If this parameter is set, it represents the number
       of seconds that must pass before an authentication token cookie is
       automatically reissued as the result of a request which requires
       authentication.  The duration is measured as the number of seconds
       since the last auth_tkt cookie was issued and 'now'.  If this value is
       ``0``, a new ticket cookie will be reissued on every request which
       requires authentication.

       A good rule of thumb: if you want auto-expired cookies based on
       inactivity: set the ``timeout`` value to 1200 (20 mins) and set the
       ``reissue_time`` value to perhaps a tenth of the ``timeout`` value
       (120 or 2 mins).  It's nonsensical to set the ``timeout`` value lower
       than the ``reissue_time`` value, as the ticket will never be reissued
       if so.  However, such a configuration is not explicitly prevented.

       Optional.

    ``max_age``

       Default: ``None``.  The max age of the auth_tkt cookie, in
       seconds.  This differs from ``timeout`` inasmuch as ``timeout``
       represents the lifetime of the ticket contained in the cookie,
       while this value represents the lifetime of the cookie itself.
       When this value is set, the cookie's ``Max-Age`` and
       ``Expires`` settings will be set, allowing the auth_tkt cookie
       to last between browser sessions.  It is typically nonsensical
       to set this to a value that is lower than ``timeout`` or
       ``reissue_time``, although it is not explicitly prevented.
       Optional.

    ``path``

       Default: ``/``. The path for which the auth_tkt cookie is valid.
       May be desirable if the application only serves part of a domain.
       Optional.

    ``http_only``

       Default: ``False``. Hide cookie from JavaScript by setting the
       HttpOnly flag. Not honored by all browsers.
       Optional.

    ``wild_domain``

       Default: ``True``. An auth_tkt cookie will be generated for the
       wildcard domain. If your site is hosted as ``example.com`` this
       will make the cookie available for sites underneath ``example.com``
       such as ``www.example.com``.
       Optional.

    ``parent_domain``

       Default: ``False``. An auth_tkt cookie will be generated for the
       parent domain of the current site. For example if your site is
       hosted under ``www.example.com`` a cookie will be generated for
       ``.example.com``. This can be useful if you have multiple sites
       sharing the same domain. This option supercedes the ``wild_domain``
       option.
       Optional.

    ``domain``

       Default: ``None``. If provided the auth_tkt cookie will only be
       set for this domain. This option is not compatible with ``wild_domain``
       and ``parent_domain``.
       Optional.

    ``hashalg``

       Default: ``sha512`` (the literal string).

       Any hash algorithm supported by Python's ``hashlib.new()`` function
       can be used as the ``hashalg``.

       Cookies generated by different instances of AuthTktAuthenticationPolicy
       using different ``hashalg`` options are not compatible. Switching the
       ``hashalg`` will imply that all existing users with a valid cookie will
       be required to re-login.

       Optional.

    ``debug``

        Default: ``False``.  If ``debug`` is ``True``, log messages to the
        Pyramid debug logger about the results of various authentication
        steps.  The output from debugging is useful for reporting to maillist
        or IRC channels when asking for support. Optional.

    ``samesite``

        Default: ``'Lax'``.  The 'samesite' option of the session cookie. Set
        the value to ``None`` to turn off the samesite option. Optional.

    .. versionchanged:: 2.0

        The default ``hashalg`` was changed from ``md5`` to ``sha512``.

    """

    parse_ticket = staticmethod(parse_ticket)  # for tests
    AuthTicket = AuthTicket  # for tests
    BadTicket = BadTicket  # for tests
    now = None  # for tests

    userid_type_decoders = {
        'int': int,
        'unicode': lambda x: utf_8_decode(x)[0],  # bw compat for old cookies
        'b64unicode': lambda x: utf_8_decode(b64decode(x))[0],
        'b64str': lambda x: b64decode(x),
    }

    userid_type_encoders = {
        int: ('int', str),
        str: ('b64unicode', lambda x: b64encode(utf_8_encode(x)[0])),
        bytes: ('b64str', lambda x: b64encode(x)),
    }

    def __init__(
        self,
        secret,
        cookie_name='auth_tkt',
        secure=False,
        include_ip=False,
        timeout=None,
        reissue_time=None,
        max_age=None,
        http_only=False,
        path="/",
        wild_domain=True,
        hashalg='sha512',
        parent_domain=False,
        domain=None,
        samesite='Lax',
    ):
        self.cookie_profile = CookieProfile(
            cookie_name=cookie_name,
            secure=secure,
            max_age=max_age,
            httponly=http_only,
            path=path,
            serializer=SimpleSerializer(),
            samesite=samesite,
        )

        self.secret = secret
        self.cookie_name = cookie_name
        self.secure = secure
        self.include_ip = include_ip
        self.timeout = timeout if timeout is None else int(timeout)
        self.reissue_time = (
            reissue_time if reissue_time is None else int(reissue_time)
        )
        self.max_age = max_age if max_age is None else int(max_age)
        self.wild_domain = wild_domain
        self.parent_domain = parent_domain
        self.domain = domain
        self.hashalg = hashalg

    def _get_cookies(self, request, value, max_age=None):
        pass

    def identify(self, request):
        """Return a dictionary with authentication information, or ``None``
        if no valid auth_tkt is attached to ``request``"""
        pass

    def forget(self, request):
        """Return a set of expires Set-Cookie headers, which will destroy
        any existing auth_tkt cookie when attached to a response"""
        pass

    def remember(self, request, userid, max_age=None, tokens=()):
        """Return a set of Set-Cookie headers; when set into a response,
        these headers will represent a valid authentication ticket.

        ``max_age``
          The max age of the auth_tkt cookie, in seconds.  When this value is
          set, the cookie's ``Max-Age`` and ``Expires`` settings will be set,
          allowing the auth_tkt cookie to last between browser sessions.  If
          this value is ``None``, the ``max_age`` value provided to the
          helper itself will be used as the ``max_age`` value.  Default:
          ``None``.

        ``tokens``
          A sequence of strings that will be placed into the auth_tkt tokens
          field.  Each string in the sequence must be of the Python ``str``
          type and must match the regex ``^[A-Za-z][A-Za-z0-9+_-]*$``.
          Tokens are available in the returned identity when an auth_tkt is
          found in the request and unpacked.  Default: ``()``.
        """
        pass


@implementer(IAuthenticationPolicy)
class SessionAuthenticationPolicy(CallbackAuthenticationPolicy):
    """A :app:`Pyramid` authentication policy which gets its data from the
    configured :term:`session`.  For this authentication policy to work, you
    will have to follow the instructions in the :ref:`sessions_chapter` to
    configure a :term:`session factory`.

    Constructor Arguments

    ``prefix``

       A prefix used when storing the authentication parameters in the
       session. Defaults to 'auth.'. Optional.

    ``callback``

       Default: ``None``.  A callback passed the userid and the
       request, expected to return ``None`` if the userid doesn't
       exist or a sequence of principal identifiers (possibly empty) if
       the user does exist.  If ``callback`` is ``None``, the userid
       will be assumed to exist with no principals.  Optional.

    ``debug``

        Default: ``False``.  If ``debug`` is ``True``, log messages to the
        Pyramid debug logger about the results of various authentication
        steps.  The output from debugging is useful for reporting to maillist
        or IRC channels when asking for support.

    """

    def __init__(self, prefix='auth.', callback=None, debug=False):
        self.callback = callback
        self.debug = debug
        self.helper = SessionAuthenticationHelper(prefix)

    def remember(self, request, userid, **kw):
        """Store a userid in the session."""
        pass

    def forget(self, request):
        """Remove the stored userid from the session."""
        pass

    def unauthenticated_userid(self, request):
        pass


class SessionAuthenticationHelper:
    """A helper for use with a :term:`security policy` which stores user data
    in the configured :term:`session`.

    Constructor Arguments

    ``prefix``

       A prefix used when storing the authentication parameters in the
       session. Defaults to 'auth.'. Optional.

    """

    def __init__(self, prefix='auth.'):
        self.userid_key = prefix + 'userid'

    def remember(self, request, userid, **kw):
        """Store a userid in the session."""
        pass

    def forget(self, request, **kw):
        """Remove the stored userid from the session."""
        pass

    def authenticated_userid(self, request):
        """Return the stored userid."""
        pass


@implementer(IAuthenticationPolicy)
class BasicAuthAuthenticationPolicy(CallbackAuthenticationPolicy):
    """A :app:`Pyramid` authentication policy which uses HTTP standard basic
    authentication protocol to authenticate users.  To use this policy you will
    need to provide a callback which checks the supplied user credentials
    against your source of login data.

    Constructor Arguments

    ``check``

       A callback function passed a username, password and request, in that
       order as positional arguments.  Expected to return ``None`` if the
       userid doesn't exist or a sequence of principal identifiers (possibly
       empty) if the user does exist.

    ``realm``

       Default: ``"Realm"``.  The Basic Auth Realm string.  Usually displayed
       to the user by the browser in the login dialog.

    ``debug``

        Default: ``False``.  If ``debug`` is ``True``, log messages to the
        Pyramid debug logger about the results of various authentication
        steps.  The output from debugging is useful for reporting to maillist
        or IRC channels when asking for support.

    **Issuing a challenge**

    Regular browsers will not send username/password credentials unless they
    first receive a challenge from the server.  The following recipe will
    register a view that will send a Basic Auth challenge to the user whenever
    there is an attempt to call a view which results in a Forbidden response::

        from pyramid.httpexceptions import HTTPUnauthorized
        from pyramid.security import forget
        from pyramid.view import forbidden_view_config

        @forbidden_view_config()
        def forbidden_view(request):
            if request.authenticated_userid is None:
                response = HTTPUnauthorized()
                response.headers.update(forget(request))
                return response
            return HTTPForbidden()
    """

    def __init__(self, check, realm='Realm', debug=False):
        self.check = check
        self.realm = realm
        self.debug = debug

    def unauthenticated_userid(self, request):
        """The userid parsed from the ``Authorization`` request header."""
        pass

    def remember(self, request, userid, **kw):
        """A no-op. Basic authentication does not provide a protocol for
        remembering the user. Credentials are sent on every request.

        """
        pass

    def forget(self, request):
        """Returns challenge headers. This should be attached to a response
        to indicate that credentials are required."""
        pass

    def callback(self, username, request):
        # Username arg is ignored. Unfortunately
        # extract_http_basic_credentials winds up getting called twice when
        # authenticated_userid is called. Avoiding that, however,
        # winds up duplicating logic from the superclass.
        credentials = extract_http_basic_credentials(request)
        if credentials:
            username, password = credentials
            return self.check(username, password, request)


HTTPBasicCredentials = namedtuple(
    'HTTPBasicCredentials', ['username', 'password']
)


def extract_http_basic_credentials(request):
    """A helper function for extraction of HTTP Basic credentials
    from a given :term:`request`.

    Returns a :class:`.HTTPBasicCredentials` 2-tuple with ``username`` and
    ``password`` attributes or ``None`` if no credentials could be found.

    """
    authorization = request.headers.get('Authorization')
    if not authorization:
        return None

    try:
        authmeth, auth = authorization.split(' ', 1)
    except ValueError:  # not enough values to unpack
        return None

    if authmeth.lower() != 'basic':
        return None

    try:
        authbytes = b64decode(auth.strip())
    except (TypeError, binascii.Error):  # can't decode
        return None

    # try utf-8 first, then latin-1; see discussion in
    # https://github.com/Pylons/pyramid/issues/898
    try:
        auth = authbytes.decode('utf-8')
    except UnicodeDecodeError:
        auth = authbytes.decode('latin-1')

    try:
        username, password = auth.split(':', 1)
    except ValueError:  # not enough values to unpack
        return None

    return HTTPBasicCredentials(username, password)
