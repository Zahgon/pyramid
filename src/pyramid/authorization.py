import warnings
from zope.interface import implementer

from pyramid.interfaces import IAuthorizationPolicy
from pyramid.location import lineage
from pyramid.util import is_nonstr_iter

# the simplest way to deprecate the attributes in security.py is to
# leave them defined there and then import/re-export them here because
# otherwise there is a difficult-to-resolve circular import between
# the two modules - in the future when we remove the deprecated code and
# move it to live here, we will be able to remove this
with warnings.catch_warnings():
    warnings.simplefilter('ignore')
    from pyramid.security import (
        ACLAllowed as _ACLAllowed,
        ACLDenied as _ACLDenied,
        Allow,
        AllPermissionsList as _AllPermissionsList,
        Authenticated,
        Deny,
        Everyone,
    )


Everyone = Everyone  # api
Authenticated = Authenticated  # api
Allow = Allow  # api
Deny = Deny  # api


# subclasses to fix __module__
class AllPermissionsList(_AllPermissionsList):
    pass


class ACLAllowed(_ACLAllowed):
    pass


class ACLDenied(_ACLDenied):
    pass


ALL_PERMISSIONS = AllPermissionsList()  # api
DENY_ALL = (Deny, Everyone, ALL_PERMISSIONS)  # api


@implementer(IAuthorizationPolicy)
class ACLAuthorizationPolicy:
    """An :term:`authorization policy` which consults an :term:`ACL`
    object attached to a :term:`context` to determine authorization
    information about a :term:`principal` or multiple principals.
    This class is a wrapper around :class:`.ACLHelper`, refer to that class for
    more detailed documentation.

    Objects of this class implement the
    :class:`pyramid.interfaces.IAuthorizationPolicy` interface.

    .. deprecated:: 2.0

        Authorization policies have been deprecated by the new security system.
        See :ref:`upgrading_auth_20` for more information.

    """

    def __init__(self):
        self.helper = ACLHelper()

    def permits(self, context, principals, permission):
        """Return an instance of
        :class:`pyramid.authorization.ACLAllowed` instance if the policy
        permits access, return an instance of
        :class:`pyramid.authorization.ACLDenied` if not."""
        pass

    def principals_allowed_by_permission(self, context, permission):
        """Return the set of principals explicitly granted the
        permission named ``permission`` according to the ACL directly
        attached to the ``context`` as well as inherited ACLs based on
        the :term:`lineage`."""
        pass


class ACLHelper:
    """A helper for use with constructing a :term:`security policy` which
    consults an :term:`ACL` object attached to a :term:`context` to determine
    authorization information about a :term:`principal` or multiple principals.
    If the context is part of a :term:`lineage`, the context's parents are
    consulted for ACL information too.

    """

    def permits(self, context, principals, permission):
        """Return an instance of :class:`pyramid.authorization.ACLAllowed` if
        the ACL allows access a user with the given principals, return an
        instance of :class:`pyramid.authorization.ACLDenied` if not.

        When checking if principals are allowed, the security policy consults
        the ``context`` for an ACL first.  If no ACL exists on the context, or
        one does exist but the ACL does not explicitly allow or deny access for
        any of the effective principals, consult the context's parent ACL, and
        so on, until the lineage is exhausted or we determine that the policy
        permits or denies.

        During this processing, if any :data:`pyramid.authorization.Deny`
        ACE is found matching any principal in ``principals``, stop
        processing by returning an
        :class:`pyramid.authorization.ACLDenied` instance (equals
        ``False``) immediately.  If any
        :data:`pyramid.authorization.Allow` ACE is found matching any
        principal, stop processing by returning an
        :class:`pyramid.authorization.ACLAllowed` instance (equals
        ``True``) immediately.  If we exhaust the context's
        :term:`lineage`, and no ACE has explicitly permitted or denied
        access, return an instance of
        :class:`pyramid.authorization.ACLDenied` (equals ``False``).

        """
        pass

    def principals_allowed_by_permission(self, context, permission):
        """Return the set of principals explicitly granted the permission
        named ``permission`` according to the ACL directly attached to the
        ``context`` as well as inherited ACLs based on the :term:`lineage`.

        When computing principals allowed by a permission, we compute the set
        of principals that are explicitly granted the ``permission`` in the
        provided ``context``.  We do this by walking 'up' the object graph
        *from the root* to the context.  During this walking process, if we
        find an explicit :data:`pyramid.authorization.Allow` ACE for a
        principal that matches the ``permission``, the principal is included in
        the allow list.  However, if later in the walking process that
        principal is mentioned in any :data:`pyramid.authorization.Deny` ACE
        for the permission, the principal is removed from the allow list.  If
        a :data:`pyramid.authorization.Deny` to the principal
        :data:`pyramid.authorization.Everyone` is encountered during the
        walking process that matches the ``permission``, the allow list is
        cleared for all principals encountered in previous ACLs.  The walking
        process ends after we've processed the any ACL directly attached to
        ``context``; a set of principals is returned.

        """
        pass
