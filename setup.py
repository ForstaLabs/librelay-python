#!/usr/bin/env python3

from setuptools import setup, find_packages

README = 'README.md'


def long_desc():
    with open(README) as f:
        return f.read()

setup(
    name='librelay',
    version='0.7.2',
    description='Forsta messaging protocol library',
    author='Forsta, Inc.',
    author_email='support@forsta.io',
    url='https://github.com/ForstaLabs/librelay-python',
    license='GPL',
    long_description=long_desc(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        'libsignal>=0.0.4',
        'aiohttp>=3.6.2',
        'protobuf>=3.7.0'
    ],
    test_suite='test',
    classifiers=[
        'Development Status :: 4 - Beta',
        # 'Development Status :: 5 - Production/Stable',
        # 'Development Status :: 6 - Mature',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries',
    ]
)
