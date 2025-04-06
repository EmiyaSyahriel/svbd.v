# svbd.v - Simple V Build Driver

What it does is just drives the V build system for projects with multiple subproject, that's it. Well, maybe with one or two additional features. Entirely written in V.

> I thought to use SQBD though, but that sounds cringe 😑

## Features
- No additional dependency, Only uses V internal libraries.
- Simple to integrate, only a single shell script, you can call it from everywhere unrestricted by your OS, you can compile it too binary too.
- Fast and lightweight, this is V after all.

### Tasks
- Build one or multiple modules
- Run a module
- Clean build artifacts
- List modules ( with diagnostics )

## Usage
This script works almost similarly as GNU Make, put a `svbd.config` file at your project root, specify all of the modules
you want to drive using this script ( make sure each module have v.mod file ), and you're ready to go.

### Installation
This script is a V Shell Script, just download the `svbd.v` file to somewhere in your devices' `$PATH` / `%PATH%`, 
or put it somewhere in your project ( embedding is allowed as long as the license notice in the file isn't changed ).

If you are on Linux or Mac, you can just `chmod +x svbd.v` and execute the file from terminal as a shell script. 
On Windows, you may need to call `v run svbd.v -- [arguments]`

> The script is also can be compiled to native binary, it works basically the same as how you use it as a shell script

### Commands
```
svbd - simple v build driver
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
	Which directory to use as module binary output directory

--lib-extension <extension>
	Specify what file extension should be used for library binaries, default = platform's format (e.g .dll, .so). 
	You don't need to add the dot (.), the build system would append it by itself. 
	If empty string is specified, no extension would be added, only leaves the file name.

--exe-extension <extension>
	Specify what file extension should be used for executable binaries, default = platform's format (e.g .exe, .app). 
	You don't need to add the dot (.), the build system would append it by itself. 
	If empty string is specified, no extension would be added, only leaves the file name.
```

### Recommended Project Folder Structure
```
|_ project1/
|  |_ v.mod
|  |_ src/
|  |  |_ source1.v
|  |  |_ source2.v
|  |  |_ ...
|  |_ ...
|_ project2/
|  |_ v.mod
|  |_ src/
|  |  |_ source1.v
|  |  |_ source2.v
|  |  |_ ...
|  |_ ...
|_ ...
|_ svbd.config
|_ ...
```

### svbd.config File Structure
This is Makefile equivalent for svbd.v, it contains all informations needed to drive your project from this script.

The module entry format is:
```
[module_type]:[module_name] [| v_compile_flags...]
```

Possible module types:
- Shared Libraries ( "l", "lib", "library", "shared", "dll", "so", "dylib" )
- Executable ( "e", "exe", "executable" )

Module names is limited to `[a-zA-Z0-9_]` to adhere with V module name standard

V Compile flags is completely optional, you can use it to add library linkage, specify backend or maybe c compiler, etc. 
But if you specify one, here is some flags you should not manually specify : `-o`, `-prod`, `-g`, `--os`, `-shared`.

Blank lines or comment lines ( line starting with "#" ) is going to be ignored.

#### Sample
```
# This is a comment
lib:csvparser
l:mysndlib    | -cc gcc -lsoundio
e:mymainapp   | -lglfw -lglew
```

## Building
It is just a shell script, no need to build anything basically. You just need the V toolchain, and that's all you need.

## Contibuting
Any code improvement or feature addition is welcome.

## License
MIT License unless explicitly stated otherwise either in a subdirectory or on top of a file source code, see [LICENSE](LICENSE)
