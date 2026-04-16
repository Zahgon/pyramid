import binascii
import os
import pickle
import time
from webob.cookies import JSONSerializer, SignedSerializer
from zope.deprecation import deprecated
from zope.interface import implementer

from pyramid.csrf import check_csrf_origin, check_csrf_token
from pyramid.interfaces import ISession
from pyramid.util import bytes_, text_


def manage_accessed(wrapped):
    """Decorator which causes a cookie to be renewed when an accessor
    method is called."""
    pass


def manage_changed(wrapped):
    """Decorator which causes a cookie to be set when a setter method
    is called."""
    pass


class PickleSerializer:
    """
    .. deprecated:: 2.0

    .. warning::

        In :app:`Pyramid` 2.0 the default ``serializer`` option changed to
        use :class:`pyramid.session.JSONSerializer`, and ``PickleSerializer``
        has been been removed from active Pyramid code.

        Pyramid will require JSON-serializable objects in :app:`Pyramid` 2.0.

        Please see :ref:`upgrading_session_20`.

    A serializer that uses the pickle protocol to dump Python data to bytes.

    This was the default serializer used by Pyramid, but has been deprecated.

    ``protocol`` may be specified to control the version of pickle used.
    Defaults to :attr:`pickle.HIGHEST_PROTOCOL`.
    """

    def __init__(self, protocol=pickle.HIGHEST_PROTOCOL):
        self.protocol = protocol

    def loads(self, bstruct):
        """Accept bytes and return a Python object."""
        pass

    def dumps(self, appstruct):
        """Accept a Python object and return bytes."""
        return pickle.dumps(appstruct, self.protocol)


deprecated(
    'PickleSerializer',
    'pyramid.session.PickleSerializer is deprecated as of Pyramid 2.0 for '
    'security concerns. Use pyramid.session.JSONSerializer or reference the '
    'narrative documentation for information on building a migration tool.',
)


JSONSerializer = JSONSerializer  # api


def BaseCookieSessionFactory(
    serializer,
    cookie_name='session',
    max_age=None,
    path='/',
    domain=None,
    secure=False,
    httponly=False,
    samesite='Lax',
    timeout=1200,
    reissue_time=0,
    set_on_exception=True,
):
    """
    Configure a :term:`session factory` which will provide cookie-based
    sessions.  The return value of this function is a :term:`session factory`,
    which may be provided as the ``session_factory`` argument of a
    :class:`pyramid.config.Configurator` constructor, or used as the
    ``session_factory`` argument of the
    :meth:`pyramid.config.Configurator.set_session_factory` method.

    The session factory returned by this function will create sessions
    which are limited to storing fewer than 4000 bytes of data (as the
    payload must fit into a single cookie).

    .. warning:

       This class provides no protection from tampering and is only intended
       to be used by framework authors to create their own cookie-based
       session factories.

    Parameters:

    ``serializer``
      An object with two methods: ``loads`` and ``dumps``.  The ``loads``
      method should accept bytes and return a Python object.  The ``dumps``
      method should accept a Python object and return bytes.  A ``ValueError``
      should be raised for malformed inputs.

    ``cookie_name``
      The name of the cookie used for sessioning. Default: ``'session'``.

    ``max_age``
      The maximum age of the cookie used for sessioning (in seconds).
      Default: ``None`` (browser scope).

    ``path``
      The path used for the session cookie. Default: ``'/'``.

    ``domain``
      The domain used for the session cookie.  Default: ``None`` (no domain).

    ``secure``
      The 'secure' flag of the session cookie. Default: ``False``.

    ``httponly``
      Hide the cookie from Javascript by setting the 'HttpOnly' flag of the
      session cookie. Default: ``False``.

    ``samesite``
      The 'samesite' option of the session cookie. Set the value to ``None``
      to turn off the samesite option.  Default: ``'Lax'``.

    ``timeout``
      A number of seconds of inactivity before a session times out. If
      ``None`` then the cookie never expires. This lifetime only applies
      to the *value* within the cookie. Meaning that if the cookie expires
      due to a lower ``max_age``, then this setting has no effect.
      Default: ``1200``.

    ``reissue_time``
      The number of seconds that must pass before the cookie is automatically
      reissued as the result of a request which accesses the session. The
      duration is measured as the number of seconds since the last session
      cookie was issued and 'now'.  If this value is ``0``, a new cookie
      will be reissued on every request accessing the session. If ``None``
      then the cookie's lifetime will never be extended.

      A good rule of thumb: if you want auto-expired cookies based on
      inactivity: set the ``timeout`` value to 1200 (20 mins) and set the
      ``reissue_time`` value to perhaps a tenth of the ``timeout`` value
      (120 or 2 mins).  It's nonsensical to set the ``timeout`` value lower
      than the ``reissue_time`` value, as the ticket will never be reissued.
      However, such a configuration is not explicitly prevented.

      Default: ``0``.

    ``set_on_exception``
      If ``True``, set a session cookie even if an exception occurs
      while rendering a view. Default: ``True``.

    .. versionadded: 1.5a3

    .. versionchanged: 1.10

       Added the ``samesite`` option and made the default ``'Lax'``.
    """
    pass


def SignedCookieSessionFactory(
    secret,
    cookie_name='session',
    max_age=None,
    path='/',
    domain=None,
    secure=False,
    httponly=False,
    samesite='Lax',
    set_on_exception=True,
    timeout=1200,
    reissue_time=0,
    hashalg='sha512',
    salt='pyramid.session.',
    serializer=None,
):
    """
    Configure a :term:`session factory` which will provide signed
    cookie-based sessions.  The return value of this
    function is a :term:`session factory`, which may be provided as
    the ``session_factory`` argument of a
    :class:`pyramid.config.Configurator` constructor, or used
    as the ``session_factory`` argument of the
    :meth:`pyramid.config.Configurator.set_session_factory`
    method.

    The session factory returned by this function will create sessions
    which are limited to storing fewer than 4000 bytes of data (as the
    payload must fit into a single cookie).

    Parameters:

    ``secret``
      A string which is used to sign the cookie. The secret should be at
      least as long as the block size of the selected hash algorithm. For
      ``sha512`` this would mean a 512 bit (64 character) secret.  It should
      be unique within the set of secret values provided to Pyramid for
      its various subsystems (see :ref:`admonishment_against_secret_sharing`).

    ``hashalg``
      The HMAC digest algorithm to use for signing. The algorithm must be
      supported by the :mod:`hashlib` library. Default: ``'sha512'``.

    ``salt``
      A namespace to avoid collisions between different uses of a shared
      secret. Reusing a secret for different parts of an application is
      strongly discouraged (see :ref:`admonishment_against_secret_sharing`).
      Default: ``'pyramid.session.'``.

    ``cookie_name``
      The name of the cookie used for sessioning. Default: ``'session'``.

    ``max_age``
      The maximum age of the cookie used for sessioning (in seconds).
      Default: ``None`` (browser scope).

    ``path``
      The path used for the session cookie. Default: ``'/'``.

    ``domain``
      The domain used for the session cookie.  Default: ``None`` (no domain).

    ``secure``
      The 'secure' flag of the session cookie. Default: ``False``.

    ``httponly``
      Hide the cookie from Javascript by setting the 'HttpOnly' flag of the
      session cookie. Default: ``False``.

    ``samesite``
      The 'samesite' option of the session cookie. Set the value to ``None``
      to turn off the samesite option.  Default: ``'Lax'``.

    ``timeout``
      A number of seconds of inactivity before a session times out. If
      ``None`` then the cookie never expires. This lifetime only applies
      to the *value* within the cookie. Meaning that if the cookie expires
      due to a lower ``max_age``, then this setting has no effect.
      Default: ``1200``.

    ``reissue_time``
      The number of seconds that must pass before the cookie is automatically
      reissued as the result of accessing the session. The
      duration is measured as the number of seconds since the last session
      cookie was issued and 'now'.  If this value is ``0``, a new cookie
      will be reissued on every request accessing the session. If ``None``
      then the cookie's lifetime will never be extended.

      A good rule of thumb: if you want auto-expired cookies based on
      inactivity: set the ``timeout`` value to 1200 (20 mins) and set the
      ``reissue_time`` value to perhaps a tenth of the ``timeout`` value
      (120 or 2 mins).  It's nonsensical to set the ``timeout`` value lower
      than the ``reissue_time`` value, as the ticket will never be reissued.
      However, such a configuration is not explicitly prevented.

      Default: ``0``.

    ``set_on_exception``
      If ``True``, set a session cookie even if an exception occurs
      while rendering a view. Default: ``True``.

    ``serializer``
      An object with two methods: ``loads`` and ``dumps``.  The ``loads``
      method should accept bytes and return a Python object.  The ``dumps``
      method should accept a Python object and return bytes.  A ``ValueError``
      should be raised for malformed inputs.  If a serializer is not passed,
      the :class:`pyramid.session.JSONSerializer` serializer will be used.

    .. warning::

        In :app:`Pyramid` 2.0 the default ``serializer`` option changed to
        use :class:`pyramid.session.JSONSerializer`. See
        :ref:`upgrading_session_20` for more information about why this
        change was made.

    .. versionadded: 1.5a3

    .. versionchanged: 1.10

        Added the ``samesite`` option and made the default ``Lax``.

    .. versionchanged: 2.0

        Changed the default ``serializer`` to be an instance of
        :class:`pyramid.session.JSONSerializer`.

    """
    pass


check_csrf_origin = check_csrf_origin  # api
deprecated(
    'check_csrf_origin',
    'pyramid.session.check_csrf_origin is deprecated as of Pyramid '
    '1.9. Use pyramid.csrf.check_csrf_origin instead.',
)

check_csrf_token = check_csrf_token  # api
deprecated(
    'check_csrf_token',
    'pyramid.session.check_csrf_token is deprecated as of Pyramid '
    '1.9. Use pyramid.csrf.check_csrf_token instead.',
)
