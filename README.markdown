## Important notice
libmesode is deprecated. Please use [libstrophe](https://github.com/strophe/libstrophe) (>= 0.11.0).
The major functionality that distinguished it from libstrophe was the manual verification of a certificate.
This has now been [implemented](https://github.com/strophe/libstrophe/pull/186) in libstrophe [0.11.0](https://github.com/strophe/libstrophe/releases/tag/0.11.0).

The other reasons for the fork are listed below. And none is worth keeping this fork around.

# libmesode

libmesode is a fork of libstrophe (http://strophe.im/libstrophe/) for use in Profanity (http://www.profanity.im/).

Reasons for forking:

- Remove Windows support
- Support only one XML Parser implementation (expat)
- Support only one SSL implementation (OpenSSL)

This simplifies maintenance of the library when used in Profanity. 

Whilst Profanity will run against libstrophe, libmesode provides extra TLS functionality such as manual SSL certificate verification.

Build Instructions
------------------

If you are building from a source control checkout, run:

    ./bootstrap.sh

to generate the `configure` script.

From the top-level directory, run the following commands:

    ./configure
    make

The public API is defined in `mesode.h` which is in the
top-level directory.

The `examples` directory contains some examples of how to
use the library; these may be helpful in addition to the
API documentation

To install on your system, as root (or using sudo):

    make install

Note, the default install path is `/usr/local/`, to specify
another path use the `--prefix` option during configure, e.g.:

    ./configure --prefix=/usr

