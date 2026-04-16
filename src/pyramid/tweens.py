import sys

from pyramid.httpexceptions import HTTPNotFound
from pyramid.util import reraise


def _error_handler(request, exc):
    # NOTE: we do not need to delete exc_info because this function
    # should never be in the call stack of the exception
    pass


def excview_tween_factory(handler, registry):
    """A :term:`tween` factory which produces a tween that catches an
    exception raised by downstream tweens (or the main Pyramid request
    handler) and, if possible, converts it into a Response using an
    :term:`exception view`.

    .. versionchanged:: 1.9
       The ``request.response`` will be remain unchanged even if the tween
       handles an exception. Previously it was deleted after handling an
       exception.

       Also, ``request.exception`` and ``request.exc_info`` are only set if
       the tween handles an exception and returns a response otherwise they
       are left at their original values.

    """
    pass


MAIN = 'MAIN'
INGRESS = 'INGRESS'
EXCVIEW = 'pyramid.tweens.excview_tween_factory'
