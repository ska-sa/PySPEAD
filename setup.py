"""SPEAD: The Streaming Protocol for Exchanging Astronomical Data"""
from distutils.core import setup, Extension
import os, glob

__version__ = '0.5.1'

def indir(dir, files): return [dir+f for f in files]
def globdir(dir, files):
    rv = []
    for f in files: rv += glob.glob(dir+f)
    return rv

setup(name = 'spead',
    version = __version__,
    description = __doc__,
    long_description = __doc__,
    license = 'GPL',
    author = 'Aaron Parsons, Jason Manley, Simon Ratcliffe',
    author_email = 'aparsons@astron.berkeley.edu',
    url = 'http://pypi.python.org/pypi/spead',
    package_dir = {'spead':'src'},
    packages = ['spead'],
    ext_modules = [
        Extension('spead._spead',
            globdir('src/_spead/',
                ['*.cpp', '*.c']),
            include_dirs = ['src/_spead/include'],
        )
    ],
    scripts = glob.glob('scripts/*'),
)
