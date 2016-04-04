#!/usr/bin/env python
# @authors: Prahlad Yeri, Oleg Kupreev
# @description: Small daemon to create a WiFi hotspot on Linux
# @license: MIT
from setuptools import setup

setup(
    name='hotspotd',
    license='MIT',
    author='Prahlad Yeri, Oleg Kupreev',
    version='0.2.4',
    description='Small daemon to create a wifi hotspot on Linux',
    py_modules=['hotspotd'],
    install_requires=[
        'Click',
    ],
    entry_points='''
        [console_scripts]
        hotspotd=hotspotd:cli
    ''',
)
