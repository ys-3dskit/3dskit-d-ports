add_repositories("3dskit git@github.com:ys-3dskit/3dskit-repo")

add_requires("3ds-zlib 1.3.1", "3dskit-dlang ~0.2.3")

includes("../toolchain/*.lua")

add_rules("mode.debug", "mode.release")

target("3ds-d-zlib")
	set_kind("static")
	set_plat("3ds")

	set_arch("arm")
	add_rules("3ds")
	set_toolchains("devkitarm")

  add_files("ys3ds/**.d")

  add_packages("3dskit-dlang")

	-- TODO: this does not belong here. it NEEDS to go. xmake won't play without it.
	add_ldflags("-specs=3dsx.specs", "-g", "-march=armv6k", "-mtune=mpcore", "-mtp=soft", "-mfloat-abi=hard", {force = true})

	-- remove default runtime
	add_dcflags("--conf=", {force=true})

	-- fix imports
	add_dcflags("-g", "-I.", {force = true})

	set_strip("debug")
