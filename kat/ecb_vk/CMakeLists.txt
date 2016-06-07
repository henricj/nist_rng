cmake_minimum_required (VERSION 2.8)

add_executable(ecb_vk ecb_vk.c)
target_link_libraries(ecb_vk nist_rng)
install(TARGETS ecb_vk DESTINATION bin)
