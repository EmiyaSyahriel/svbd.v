# SVBD - Simple V Build Drivers

What it does is just drives the V build system, that's it. Well, maybe with one or two additional features. Entirely written in V.

> I thought to use SQBD though, but that sounds cringe 😑

## Usage
### As Shell Script
This script is a V Shell Script, just download the `svbd.v` file to somewhere in your devices' $PATH%PATH%, or put it somewhere in your project.
If you are on Linux or Mac, you can just `chmod +x svbd.v` and execute the file from terminal. On Windows, you may need to call `v run svbd.v -- [arguments]`

### As Executable
The script is also can be compiled to native binary using V, the rest of the steps is just the same like using it the shell script way. 

### Commands
```
println(r"svbd - simple v build driver
usage : svbd.v [OPTIONS] [module_name...]

You can specify multiple modules to build

This script reads all of the config from 'svbd.config' in current working directory

-h, --help
	Show this help and exit

-l, --list
	List all modules, also checks for module validity e.g folder exists, v.mod file
	and then exits

-r, --run
	Run the code instead of building the binary
	[!] You can only run the first specified executable module, the rest will be ignored

--clean
	Clean the build artifacts
	[!] If no modules is specified, all of the modules will be cleared

-prod, -rel, --release, --production
	Build a production / release build

-g, --debug
	Build a debug build ( default )

-f, --force
	Force build even if destination binary file is newer than source code

--os <os>
	Which OS to target, check `v help build` for which OS that is supported

-v, --verbose
	Make the build.v verbose

-vv, --v-verbose
	Make the V compiler verbose

-o <directory>, --output <directory>
	Which directory as build directory

--lib-extension <extension>
	Specify what file extension should be used for library binaries, default = platform's format (e.g .dll, .so). 
	You don't need to add the dot (.), the build system would append it by itself. 
	If empty string is specified, no extension would be added, only leaves the file name.

--exe-extension <extension>
	Specify what file extension should be used for executable binaries, default = platform's format (e.g .exe, .app). 
	You don't need to add the dot (.), the build system would append it by itself. 
	If empty string is specified, no extension would be added, only leaves the file name.
```

## Building
It is just a shell script, no need to build anything basically.

## Contibuting
Any code improvement or feature addition is welcome.

## License
MIT License unless explicitly stated otherwise, see [LICENSE](LICENSE)
