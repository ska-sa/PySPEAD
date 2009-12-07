"""SPEAD: The Streaming Protocol for Exchanging Astronomical Data"""
from distutils.core import setup
import os, glob

__version__ = '0.0.1'

setup(name = 'spead',
    version = __version__,
    description = __doc__,
    long_description = __doc__,
    license = 'GPL',
    author = 'Simon Ratcliffe, Aaron Parsons',
    author_email = 'sratcliffe@gmail.com, aparsons@astron.berkeley.edu',
    url = 'http://pypi.python.org/pypi/spead',
    package_dir = {'spead':'src'},
    packages = ['spead'],
    scripts = glob.glob('scripts/*'),
)
