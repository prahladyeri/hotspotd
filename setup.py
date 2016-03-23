#!/usr/bin/env python
# @author: Prahlad Yeri
# @description: Small daemon to create a wifi hotspot on linux
# @license: MIT
from setuptools import setup, find_packages
from hotspotd import __version__

setup(
    name='hotspotd',
    license='MIT',
    author='Prahlad Yeri',
    version=__version__,
    description='Small daemon to create a wifi hotspot on linux',
    py_modules=['hotspotd'],
    package_data={'hotspotd': ['run.dat']},
    # packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Click',
    ],
    entry_points='''
        [console_scripts]
        hotspotd=hotspotd:cli
    ''',
)
