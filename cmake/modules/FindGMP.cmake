# vim: set ts=2 shiftwidth=2 expandtab:
# - Find GMP/MPIR libraries and headers
# This module defines the following variables:
#
# GMP_FOUND         - true if GMP/MPIR was found
# GMP_INCLUDE_DIRS  - include search path
# GMP_LIBARIES      - libraries to link with

find_path(GMP_INCLUDE_DIRS NAMES gmp.h
          PATHS "$ENV{PROGRAMFILES}/mpir/include"
          DOC "The gmp include directory"
)

if(WIN32)
  find_library(GMP_LIBRARIES NAMES mpir
                PATHS "$ENV{PROGRAMFILES}/mpir/lib"
                DOC "The MPIR library"
  )
else(WIN32)
  find_library(GMP_LIBRARIES NAMES gmp
                DOC "The GMP library"
  )
endif(WIN32)

# handle the QUIET and REQUIRED arguments and set GMP_FOUND to TRUE if
# all listed variables are true
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMP DEFAULT_MSG GMP_LIBRARIES GMP_INCLUDE_DIRS)
