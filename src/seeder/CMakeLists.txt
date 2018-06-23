# Copyright (c) 2018 The Luxcore developers

project(lux-seeder)

include_directories(.)

add_executable(lux-seeder
	luxseeder.cpp
	db.cpp
	dns.cpp
	main.cpp
)

target_link_libraries(lux-seeder common)
