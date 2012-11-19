#!/usr/bin/python2
# -*- coding: utf-8 -*-

# Keystone LDAP
# Copyright (C) 2010-2012 Grid Dynamics Consulting Services, Inc
# All Rights Reserved
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.


"""
Keystone LDAP plugin
"""
import os
from setuptools import setup, find_packages, findall


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name='keystone-ldap',
    version='1.0',
    url='http://github.com/altai/keystone-ldap/',
    license='Apache 2.0',
    author='Alessio Ababilov',
    author_email='aababilov@griddynamics.com',
    description='Keystone LDAP plugin',
    long_description=__doc__,
    packages=find_packages(exclude=["bin", "tests"]),
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    test_suite='tests'
)
