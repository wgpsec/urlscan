#!/usr/bin/env python
'''
Copyright (C) 2020, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

NAME = 'Wordfence (Defiant)'


def is_waf(self):
    schemes = [
        self.matchHeader(('Server', r'wf[_\-]?WAF')),
        self.matchContent(r"Generated by Wordfence"),
        self.matchContent(r'broke one of (the )?Wordfence (advanced )?blocking rules'),
        self.matchContent(r"/plugins/wordfence")
    ]
    if any(i for i in schemes):
        return True
    return False
