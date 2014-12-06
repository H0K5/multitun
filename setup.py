#!/usr/bin/env python2

from setuptools import setup, find_packages

setup(
    name = 'multitun',
    version = '0.9',
    packages = find_packages(),
    scripts = ['multitun.py'],
    description='Tunnel net traffic over a harmless looking WebSocket',
    url='https://github.com/covertcodes/multitun',
    install_requires=['python-pytun >= 2.2',
                      'iniparse >= 0.4',
                      'Twisted >= 14.0.2',
                      'autobahn >= 0.9.2',
                      'dpkt-fix == 1.7',
                      'pycrypto >= 2.6.1',
                      'streql'
                      ],
)

