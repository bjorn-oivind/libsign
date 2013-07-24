# libsign

## Description

A simple library to perform a subset of the operations defined by PGP (RFC #4880).
Its primary use for yours truly is to verify signatures created by GPG and, at a later date, to generate them.

## Requirements
libsign requires [GMP](http://gmplib.org/) - an arbitrary precision library - to work.

Apart from a C-compiler and make, the build system of libsign also requires [CMake](http://www.cmake.org/) in order to check the dependencies and create the build-files you need.

## Example

Please have a look at some of the tests in the "tests/" directory for some examples of use.
The API is subject to change without any notice.

## Written By

[Bjørn Øivind Bjørnsen](https://github.com/bjorn-oivind)
