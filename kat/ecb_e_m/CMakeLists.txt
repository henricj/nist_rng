cmake_minimum_required (VERSION 2.8)

add_executable(ecb_e_m ecb_e_m.c)
target_link_libraries(ecb_e_m nist_rng)
install(TARGETS ecb_e_m DESTINATION bin)
