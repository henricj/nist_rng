cmake_minimum_required (VERSION 2.8)

add_executable(nist_ctr_drbg main.c)
target_link_libraries(nist_ctr_drbg nist_rng)
install(TARGETS nist_ctr_drbg DESTINATION bin)
