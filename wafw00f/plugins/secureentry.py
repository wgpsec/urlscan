#!/usr/bin/env python
'''
Copyright (C) 2020, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

NAME = 'Secure Entry (United Security Providers)'


def is_waf(self):
    schemes = [
        self.matchHeader(('Server', 'Secure Entry Server'))
    ]
    if any(i for i in schemes):
        return True
    return False
