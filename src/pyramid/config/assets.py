import os
import pkg_resources
import sys
from zope.interface import implementer

from pyramid.config.actions import action_method
from pyramid.exceptions import ConfigurationError
from pyramid.interfaces import PHASE1_CONFIG, IPackageOverrides
from pyramid.threadlocal import get_current_registry


class OverrideProvider(pkg_resources.DefaultProvider):
    def __init__(self, module):
        pkg_resources.DefaultProvider.__init__(self, module)
        self.module_name = module.__name__

    def _get_overrides(self):
        reg = get_current_registry()
        overrides = reg.queryUtility(IPackageOverrides, self.module_name)
        return overrides

    def get_resource_filename(self, manager, resource_name):
        """Return a true filesystem path for resource_name,
        co-ordinating the extraction with manager, if the resource
        must be unpacked to the filesystem.
        """
        pass

    def get_resource_stream(self, manager, resource_name):
        """Return a readable file-like object for resource_name."""
        pass

    def get_resource_string(self, manager, resource_name):
        """Return a string containing the contents of resource_name."""
        pass

    def has_resource(self, resource_name):
        pass

    def resource_isdir(self, resource_name):
        overrides = self._get_overrides()
        if overrides is not None:
            result = overrides.isdir(resource_name)
            if result is not None:
                return result
        return pkg_resources.DefaultProvider.resource_isdir(
            self, resource_name
        )

    def resource_listdir(self, resource_name):
        pass


@implementer(IPackageOverrides)
class PackageOverrides:
    # pkg_resources arg in kw args below for testing
    def __init__(self, package, pkg_resources=pkg_resources):
        loader = self._real_loader = getattr(package, '__loader__', None)
        if isinstance(loader, self.__class__):
            self._real_loader = None
        # We register ourselves as a __loader__ *only* to support the
        # setuptools _find_adapter adapter lookup; this class doesn't
        # actually support the PEP 302 loader "API".  This is
        # excusable due to the following statement in the spec:
        # ... Loader objects are not
        # required to offer any useful functionality (any such functionality,
        # such as the zipimport get_data() method mentioned above, is
        # optional)...
        # A __loader__ attribute is basically metadata, and setuptools
        # uses it as such.
        package.__loader__ = self
        # we call register_loader_type for every instantiation of this
        # class; that's OK, it's idempotent to do it more than once.
        pkg_resources.register_loader_type(self.__class__, OverrideProvider)
        self.overrides = []
        self.overridden_package_name = package.__name__

    def insert(self, path, source):
        if not path or path.endswith('/'):
            override = DirectoryOverride(path, source)
        else:
            override = FileOverride(path, source)
        self.overrides.insert(0, override)
        return override

    def filtered_sources(self, resource_name):
        for override in self.overrides:
            o = override(resource_name)
            if o is not None:
                yield o

    def get_spec(self, resource_name):
        pass

    def get_filename(self, resource_name):
        for source, path in self.filtered_sources(resource_name):
            result = source.get_filename(path)
            if result is not None:
                return result

    def get_stream(self, resource_name):
        pass

    def get_string(self, resource_name):
        pass

    def has_resource(self, resource_name):
        pass

    def isdir(self, resource_name):
        for source, path in self.filtered_sources(resource_name):
            result = source.isdir(path)
            if result is not None:
                return result

    def listdir(self, resource_name):
        pass

    @property
    def real_loader(self):
        pass

    def get_data(self, path):
        """See IPEP302Loader."""
        pass

    def is_package(self, fullname):
        """See IPEP302Loader."""
        pass

    def get_code(self, fullname):
        """See IPEP302Loader."""
        pass

    def get_source(self, fullname):
        """See IPEP302Loader."""
        pass


class DirectoryOverride:
    def __init__(self, path, source):
        self.path = path
        self.pathlen = len(self.path)
        self.source = source

    def __call__(self, resource_name):
        if resource_name.startswith(self.path):
            new_path = resource_name[self.pathlen :]
            return self.source, new_path


class FileOverride:
    def __init__(self, path, source):
        self.path = path
        self.source = source

    def __call__(self, resource_name):
        if resource_name == self.path:
            return self.source, ''


class PackageAssetSource:
    """
    An asset source relative to a package.

    If this asset source is a file, then we expect the ``prefix`` to point
    to the new name of the file, and the incoming ``resource_name`` will be
    the empty string, as returned by the ``FileOverride``.

    """

    def __init__(self, package, prefix):
        self.package = package
        if hasattr(package, '__name__'):
            self.pkg_name = package.__name__
        else:
            self.pkg_name = package
        self.prefix = prefix

    def get_path(self, resource_name):
        return f'{self.prefix}{resource_name}'

    def get_spec(self, resource_name):
        pass

    def get_filename(self, resource_name):
        path = self.get_path(resource_name)
        if pkg_resources.resource_exists(self.pkg_name, path):
            return pkg_resources.resource_filename(self.pkg_name, path)

    def get_stream(self, resource_name):
        pass

    def get_string(self, resource_name):
        pass

    def exists(self, resource_name):
        path = self.get_path(resource_name)
        if pkg_resources.resource_exists(self.pkg_name, path):
            return True

    def isdir(self, resource_name):
        path = self.get_path(resource_name)
        if pkg_resources.resource_exists(self.pkg_name, path):
            return pkg_resources.resource_isdir(self.pkg_name, path)

    def listdir(self, resource_name):
        pass


class FSAssetSource:
    """
    An asset source relative to a path in the filesystem.

    """

    def __init__(self, prefix):
        self.prefix = prefix

    def get_path(self, resource_name):
        if resource_name:
            path = os.path.join(self.prefix, resource_name)
        else:
            path = self.prefix
        return path

    def get_spec(self, resource_name):
        pass

    def get_filename(self, resource_name):
        path = self.get_path(resource_name)
        if os.path.exists(path):
            return path

    def get_stream(self, resource_name):
        pass

    def get_string(self, resource_name):
        pass

    def exists(self, resource_name):
        path = self.get_filename(resource_name)
        if path is not None:
            return True

    def isdir(self, resource_name):
        path = self.get_filename(resource_name)
        if path is not None:
            return os.path.isdir(path)

    def listdir(self, resource_name):
        pass


class AssetsConfiguratorMixin:
    def _override(
        self, package, path, override_source, PackageOverrides=PackageOverrides
    ):
        pass

    @action_method
    def override_asset(self, to_override, override_with, _override=None):
        """Add a :app:`Pyramid` asset override to the current
        configuration state.

        ``to_override`` is an :term:`asset specification` to the
        asset being overridden.

        ``override_with`` is an :term:`asset specification` to the
        asset that is performing the override. This may also be an absolute
        path.

        See :ref:`assets_chapter` for more
        information about asset overrides."""
        pass

    override_resource = override_asset  # bw compat
