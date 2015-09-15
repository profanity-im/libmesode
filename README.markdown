# libmesode

libmesode is a fork of libstrophe (http://strophe.im/libstrophe/) for use in Profanity (http://www.profanity.im/).

Reasons for forking:

- Remove Windows support
- Support only one XML Parser implementation (expat)
- Support only one SSL implementation (OpenSSL)

This simplifies maintenance of the library when used in Profanity. 

## Build Instructions

If you are building from a source control checkout, run:

    ./bootstrap.sh

to generate the `configure` script.

From the top-level directory, run the following commands:

    ./configure
    make

This will create a static library, also in the top-level
directory, which can be linked into other programs. The 
public API is defined in `strophe.h` which is also in the
top-level directory.

The `examples` directory contains some examples of how to
use the library; these may be helpful in addition to the
API documentation

To install on your system, as root (or using sudo):

    make install

Note, the default install path is `/usr/local/`, to specify
another path use the `--prefix` option during configure, e.g.:

    ./configure --prefix=/usr

## Documentation

API documentation is inline with the code and conforms to Doxygen
standards. You can generate an HTML version of the API documentation
by running:

    doxygen

Then open `docs/html/index.html`.
