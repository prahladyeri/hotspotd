#!/usr/bin/env python
# @authors: Prahlad Yeri, Oleg Kupreev
# @description: Small daemon to create a wifi hotspot on linux
# @license: MIT
from setuptools import setup

setup(
    name='hotspotd',
    license='MIT',
    author='Prahlad Yeri',
    version='0.2.1',
    description='Small daemon to create a wifi hotspot on linux',
    py_modules=['hotspotd'],
    package_data={'hotspotd': ['run.dat']},
    include_package_data=True,
    install_requires=[
        'Click',
    ],
    entry_points='''
        [console_scripts]
        hotspotd=hotspotd:cli
    ''',
)
