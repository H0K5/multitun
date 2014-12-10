#!/usr/bin/env python2

import os
import sys
from setuptools import setup, find_packages


if os.name == 'nt':
    requires=['iniparse >= 0.4',
        'Twisted >= 14.0.2',
        'autobahn >= 0.9.2',
        'dpkt-fix == 1.7',
        'pycrypto >= 2.6.1'
    ]

else:
    u = os.uname()[0]

    if u == 'Linux':
        requires=['python-pytun >= 2.2',
            'iniparse >= 0.4',
            'Twisted >= 14.0.2',
            'autobahn >= 0.9.2',
            'dpkt-fix == 1.7',
            'pycrypto >= 2.6.1',
            'streql'
        ]

    elif u == 'Darwin' or u[len(u)-3:] == 'BSD':
        requires=['iniparse >= 0.4',
            'Twisted >= 14.0.2',
            'autobahn >= 0.9.2',
            'dpkt-fix == 1.7',
            'pycrypto >= 2.6.1',
            'streql'
        ]

    else:
        print "Platform not supported"
        sys.exit()


setup(
    name = 'multitun',
    version = '0.10',
    packages = find_packages(),
    scripts = ['multitun.py'],
    description='Tunnel net traffic over a harmless looking WebSocket',
    url='https://github.com/covertcodes/multitun',
    install_requires=requires
)

