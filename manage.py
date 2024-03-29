﻿#!/usr/bin/env python
#--*-- coding: utf-8 --
from django.core.management import setup_environ, ManagementUtility
import imp
try:
    imp.find_module('settings') # Assumed to be in the same directory.
except ImportError:
    import sys
    sys.stderr.write(
        "Error: Can't find the file 'settings.py' in the directory "
        "containing %r. It appears you've customized things.\nYou'll have to "
        "run django-admin.py, passing it your settings module.\n" % __file__
        )
    sys.exit(1)

import settings

if __name__ == "__main__":
    setup_environ(settings)
    import primate
    primate.patch()
    ManagementUtility().execute()