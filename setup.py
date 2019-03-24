#!/usr/bin/env python3

from setuptools import setup, find_packages

README = 'README.md'


def long_desc():
    try:
        import pypandoc
    except ImportError:
        with open(README) as f:
            return f.read()
    else:
        return pypandoc.convert(README, 'rst')

setup(
    name='librelay',
    version='0.7.0',
    description='Forsta messaging protocol library',
    author='Justin Mayfield',
    author_email='tooker@gmail.com',
    url='https://github.com/ForstaLabs/librelay-python',
    license='GPL',
    long_description=long_desc(),
    packages=find_packages(),
    install_requires=[
        'libsignal>=0.0.4',
        'aiohttp>=3.5.4',
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
