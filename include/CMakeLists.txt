cmake_minimum_required (VERSION 2.8)

set(NIST_RNG_H_FILES
    nist_aes_padlock.h
    nist_aes_rijndael.h
    nist_config.h
    nist_ctr_drbg_aes128.h
    nist_ctr_drbg_aes256.h
    nist_ctr_drbg.h
    rijndael.h
)

foreach (file ${NIST_RNG_H_FILES})
    install(FILES ${file} DESTINATION include/nist_rng)
endforeach()
