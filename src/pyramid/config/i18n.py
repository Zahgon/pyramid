from pyramid.config.actions import action_method
from pyramid.exceptions import ConfigurationError
from pyramid.interfaces import ILocaleNegotiator, ITranslationDirectories
from pyramid.path import AssetResolver


class I18NConfiguratorMixin:
    @action_method
    def set_locale_negotiator(self, negotiator):
        """
        Set the :term:`locale negotiator` for this application.  The
        :term:`locale negotiator` is a callable which accepts a
        :term:`request` object and which returns a :term:`locale
        name`.  The ``negotiator`` argument should be the locale
        negotiator implementation or a :term:`dotted Python name`
        which refers to such an implementation.

        Later calls to this method override earlier calls; there can
        be only one locale negotiator active at a time within an
        application.  See :ref:`activating_translation` for more
        information.

        .. note::

           Using the ``locale_negotiator`` argument to the
           :class:`pyramid.config.Configurator` constructor can be used to
           achieve the same purpose.
        """
        pass

    def _set_locale_negotiator(self, negotiator):
        locale_negotiator = self.maybe_dotted(negotiator)
        self.registry.registerUtility(locale_negotiator, ILocaleNegotiator)

    @action_method
    def add_translation_dirs(self, *specs, **kw):
        """Add one or more :term:`translation directory` paths to the
        current configuration state.  The ``specs`` argument is a
        sequence that may contain absolute directory paths
        (e.g. ``/usr/share/locale``) or :term:`asset specification`
        names naming a directory path (e.g. ``some.package:locale``)
        or a combination of the two.

        Example:

        .. code-block:: python

           config.add_translation_dirs('/usr/share/locale',
                                       'some.package:locale')

        The translation directories are defined as a list in which
        translations defined later have precedence over translations defined
        earlier.

        By default, consecutive calls to ``add_translation_dirs`` will add
        directories to the start of the list. This means later calls to
        ``add_translation_dirs`` will have their translations trumped by
        earlier calls. If you explicitly need this call to trump an earlier
        call then you may set ``override`` to ``True``.

        If multiple specs are provided in a single call to
        ``add_translation_dirs``, the directories will be inserted in the
        order they're provided (earlier items are trumped by later items).

        .. versionchanged:: 1.8

           The ``override`` parameter was added to allow a later call
           to ``add_translation_dirs`` to override an earlier call, inserting
           folders at the beginning of the translation directory list.

        """
        pass
