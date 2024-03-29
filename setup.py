#!/usr/bin/env python3

"""Parse Email Files
"""
import configparser

from setuptools import find_packages, setup  # noqa: H301

NAME = "parse-emails"
# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

# Converting Pipfile to requirements style list because setup expects requirements.txt file.
parser = configparser.ConfigParser()
parser.read("Pipfile")
install_requires = [f'{key}{value}'.replace('\"', '').replace('*', '') for key, value in parser['packages'].items()]

with open('README.md') as f:
    readme = f.read()

setup(
    use_scm_version={
        'local_scheme': lambda a: ""
    },
    setup_requires=['setuptools_scm'],
    name=NAME,
    description="A Python library to parse email files",
    author_email="",
    url="https://github.com/demisto/email-parser",
    keywords=["Demisto"],
    install_requires=install_requires,
    packages=find_packages(),
    include_package_data=True,
    long_description=readme,
    long_description_content_type='text/markdown',
    license='MIT',
    classifiers=[
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: Implementation :: CPython'
    ],
    python_requires=">=3.7",
    author="Demisto"
)
