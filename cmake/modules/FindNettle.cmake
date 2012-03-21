# - Find nettle libraries and headers.
# This module defines the following variables:
#
# Nettle_FOUND          - true if nettle was found.
# Nettle_INCLUDE_DIRS   - include search path
# Nettle_LIBRARIES      - libraries to link

find_path(Nettle_INCLUDE_DIR NAMES nettle-types.h
          PATH_SUFFIXES nettle
          PATHS "$ENV{PROGRAMFILES}/nettle/include"
          DOC "The Nettle include directory"
)

find_library(Nettle_LIBRARY NAMES nettle
             PATHS "$ENV{PROGRAMFILES}/nettle/lib"
             DOC "The nettle library"
)

# if we are on *nix, we need to find gmp and hogweed.
# if we are on win32, we need to find mpir instead of gmp, hogweed is compiled into nettle.
if(WIN32)

  find_path(Gmp_INCLUDE_DIR NAMES gmp.h
            PATHS "$ENV{PROGRAMFILES}/mpir/include"
			DOC "The MPIR include directory"
  )

  find_library(Gmp_LIBRARY NAMES mpir
               PATHS "$ENV{PROGRAMFILES}/mpir/lib"
               DOC "Nettle dependency mpir"
  )

else(WIN32)

  find_path(Gmp_INCLUDE_DIR NAMES gmp.h
            DOC "The GMP include directory")

  find_library(Gmp_LIBRARY NAMES gmp
               DOC "Nettle dependency gmp"
  )

  find_library(Hogweed_LIBRARY NAMES hogweed
               DOC "Hogweed library from nettle"
  )

endif()

# handle the QUIET and REQUIRED arguments and set NETTLE_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
if(WIN32)
  find_package_handle_standard_args(Nettle DEFAULT_MSG Nettle_LIBRARY Nettle_INCLUDE_DIR Gmp_LIBRARY Gmp_INCLUDE_DIR)
else(WIN32)
  find_package_handle_standard_args(Nettle DEFAULT_MSG Nettle_LIBRARY Nettle_INCLUDE_DIR Hogweed_LIBRARY Gmp_LIBRARY Gmp_INCLUDE_DIR)
endif()

set(Nettle_FOUND ${NETTLE_FOUND})
unset(NETTLE_FOUND)

if(Nettle_FOUND)
  set(Nettle_LIBRARIES ${Nettle_LIBRARY} ${Hogweed_LIBRARY} ${Hogweed_LIBRARY} ${Gmp_LIBRARY})
  set(Nettle_INCLUDE_DIRS ${Nettle_INCLUDE_DIR} ${Gmp_INCLUDE_DIR})
endif()

mark_as_advanced(Nettle_INCLUDE_DIR Nettle_LIBRARY Hogweed_LIBRARY Gmp_LIBRARY Gmp_INCLUDE_DIR)

# vi: set ts=2 shiftwidth=2 expandtab :
