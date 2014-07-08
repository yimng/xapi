#!/usr/bin/env python
#
# extauth-hook-JIT.py
#
# This module can be called directly as a plugin.  It handles
# Active Directory being enabled or disabled as the hosts external_auth_type, 
# or subjects being added or removed while AD is the external_auth_type, 
# or xapi starting or stopping while AD is the external_auth_type.
#
# Alternatively, the extauth-hook module can be called, which will
# dispatch to the correct extauth-hook-<type>.py module automatically.

import XenAPIPlugin
import XenAPI
import sys
import syslog


def log_err(err):
    print >>sys.stderr, err
    syslog.syslog(syslog.LOG_USER | syslog.LOG_ERR, "%s: %s" % (sys.argv[0], err))


def after_extauth_enable(session, args):
    pass

def after_xapi_initialize(session, args):
    pass

def after_subject_add(session, args):
    pass

def after_subject_remove(session, args):
    pass

def after_roles_update(session, args):
    pass

def before_extauth_disable(session, args):
    pass

# The dispatcher
if __name__ == "__main__":
    dispatch_tbl = {
        "after-extauth-enable":  after_extauth_enable,
        "after-xapi-initialize": after_xapi_initialize, 
        "after-subject-add":     after_subject_add, 
        "after-subject-remove":  after_subject_remove, 
        "after-roles-update":    after_roles_update, 
        "before-extauth-disable":before_extauth_disable,
    }
    XenAPIPlugin.dispatch(dispatch_tbl)

