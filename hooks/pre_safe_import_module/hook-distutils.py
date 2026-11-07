# -*- mode: python ; coding: utf-8 -*-
"""Skip PyInstaller's vendored-``distutils`` alias.

Python 3.12 dropped ``distutils`` from the standard library, so PyInstaller
maps ``setuptools._distutils`` onto the top-level name ``distutils`` as soon as
anything imports it. NetScope excludes ``distutils`` from the bundle, and the
alias then collides with that exclusion and aborts the build with::

    ValueError: Target module "distutils" already imported as
    "ExcludedModule('distutils',)".

The only importer in the bundle is ``cffi._shimmed_dist_utils``, which wants
distutils for *compiling* C extensions - something NetScope never does. Not
adding the alias therefore keeps the exclusion intact and keeps setuptools out
of the executable.

The hook replaces PyInstaller's built-in ``pre_safe_import_module`` hook for
``distutils``: user hooks have a higher priority, so only this one runs.
"""


def pre_safe_import_module(api):
    """Deliberately does nothing - the vendored distutils alias is unwanted."""
    return
