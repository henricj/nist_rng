cmake_minimum_required (VERSION 2.8)

include_directories(${PROJECT_SOURCE_DIR})

set(NIST_RNG_C_FILES
    diffusion.c
    dump.c
    nist_aes_padlock.c
    nist_ctr_drbg.c
    rijndael.c
    runtime.c
)

add_library(nist_rng STATIC ${NIST_RNG_C_FILES})

install(TARGETS nist_rng DESTINATION lib)
