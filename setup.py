"""SPEAD: The Streaming Protocol for Exchanging Astronomical Data"""

import sys
from distutils.core import setup, Extension
import glob

__version__ = '0.5.2'


def indir(direc, files):
    return [direc + file_ for file_ in files]


def globdir(direc, files):
    rv = []
    for file_ in files:
        rv += glob.glob(direc + file_)
    return rv

setup(name='spead',
      version=__version__,
      description=__doc__,
      long_description=__doc__,
      license='GPL',
      author='Aaron Parsons, Jason Manley, Simon Ratcliffe',
      author_email='aparsons@astron.berkeley.edu',
      url='http://pypi.python.org/pypi/spead',
      package_dir={'spead64_40': 'src', 'spead64_48': 'src'},
      packages=['spead64_40', 'spead64_48'],
      ext_modules=[
          Extension('spead64_40._spead',
                    globdir('src/_spead/', ['*.cpp', '*.c']),
                    include_dirs=['src/_spead/include'],
                    define_macros=[('SPEAD_ADDRSIZE', '40')],
                    ),
          Extension('spead64_48._spead',
                    globdir('src/_spead/', ['*.cpp', '*.c']),
                    include_dirs=['src/_spead/include'],
                    define_macros=[('SPEAD_ADDRSIZE', '48')],
                    ),

      ],
      scripts=glob.glob('scripts/*'),
      install_requires=['numpy>=1.17' if sys.version_info >= (3, 5) else 'numpy<1.17'],
      )
