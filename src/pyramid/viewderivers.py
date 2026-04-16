import inspect
from zope.interface import implementer, provider

from pyramid import renderers
from pyramid.csrf import check_csrf_origin, check_csrf_token
from pyramid.exceptions import ConfigurationError
from pyramid.httpexceptions import HTTPForbidden
from pyramid.interfaces import (
    IDebugLogger,
    IDefaultCSRFOptions,
    IDefaultPermission,
    IResponse,
    ISecurityPolicy,
    IViewMapper,
    IViewMapperFactory,
)
from pyramid.response import Response
from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.util import (
    is_bound_method,
    is_unbound_method,
    object_description,
    takes_one_arg,
)
from pyramid.view import render_view_to_response


def view_description(view):
    try:
        return view.__text__
    except AttributeError:
        # custom view mappers might not add __text__
        return object_description(view)


def requestonly(view, attr=None):
    return takes_one_arg(view, attr=attr, argname='request')


@implementer(IViewMapper)
@provider(IViewMapperFactory)
class DefaultViewMapper:
    def __init__(self, **kw):
        self.attr = kw.get('attr')

    def __call__(self, view):
        if is_unbound_method(view) and self.attr is None:
            raise ConfigurationError(
                'Unbound method calls are not supported, please set the '
                'class as your `view` and the method as your `attr`'
            )

        if inspect.isclass(view):
            view = self.map_class(view)
        else:
            view = self.map_nonclass(view)
        return view

    def map_class(self, view):
        pass

    def map_nonclass(self, view):
        # We do more work here than appears necessary to avoid wrapping the
        # view unless it actually requires wrapping (to avoid function call
        # overhead).
        pass

    def map_class_requestonly(self, view):
        # its a class that has an __init__ which only accepts request
        pass

    def map_class_native(self, view):
        # its a class that has an __init__ which accepts both context and
        # request
        pass

    def map_nonclass_requestonly(self, view):
        # its a function that has a __call__ which accepts only a single
        # request argument
        pass

    def map_nonclass_attr(self, view):
        # its a function that has a __call__ which accepts both context and
        # request, but still has an attr
        pass


def wraps_view(wrapper):
    def inner(view, info):
        pass

    return inner


def preserve_view_attrs(view, wrapper):
    if view is None:
        return wrapper

    if wrapper is view:
        return view

    original_view = getattr(view, '__original_view__', None)

    if original_view is None:
        original_view = view

    wrapper.__wraps__ = view
    wrapper.__original_view__ = original_view
    wrapper.__module__ = view.__module__
    wrapper.__doc__ = view.__doc__

    try:
        wrapper.__name__ = view.__name__
    except AttributeError:
        wrapper.__name__ = repr(view)

    # attrs that may not exist on "view", but, if so, must be attached to
    # "wrapped view"
    for attr in (
        '__permitted__',
        '__call_permissive__',
        '__permission__',
        '__predicated__',
        '__predicates__',
        '__accept__',
        '__order__',
        '__text__',
    ):
        try:
            setattr(wrapper, attr, getattr(view, attr))
        except AttributeError:
            pass

    return wrapper


def mapped_view(view, info):
    pass


mapped_view.options = ('mapper', 'attr')


def owrapped_view(view, info):
    pass


owrapped_view.options = ('name', 'wrapper')


def http_cached_view(view, info):
    pass


http_cached_view.options = ('http_cache',)


def secured_view(view, info):
    pass


secured_view.options = ('permission',)


def _secured_view(view, info):
    pass


def _authdebug_view(view, info):
    # XXX this view logic is slightly different from the _secured_view above
    # because we want it to run in more situations than _secured_view - we are
    # trying to log helpful info about basically any view that is executed -
    # basically we only skip it if it's a default exception view with no
    # special permissions

    pass


def rendered_view(view, info):
    # one way or another this wrapper must produce a Response (unless
    # the renderer is a NullRendererHelper)
    pass


rendered_view.options = ('renderer',)


def decorated_view(view, info):
    pass


decorated_view.options = ('decorator',)


def csrf_view(view, info):
    pass


csrf_view.options = ('require_csrf',)

VIEW = 'VIEW'
INGRESS = 'INGRESS'
