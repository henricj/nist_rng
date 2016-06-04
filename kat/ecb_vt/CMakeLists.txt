cmake_minimum_required (VERSION 2.8)

add_executable(ecb_vt ecb_vt.c)
target_link_libraries(ecb_vt nist_rng)
install(TARGETS ecb_vt DESTINATION bin)
