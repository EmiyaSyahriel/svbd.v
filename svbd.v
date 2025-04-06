#!/usr/bin/env -S v -raw-vsh-tmp-prefix .vsh_run_tmp run
/**
 * Copyright 2025 EmiyaSyahriel
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
 * associated documentation files (the “Software”), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do 
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial 
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
 * LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

import os
import regex

/**
 * SVBD - Simple V Build Driver
 *
 * It just simply drives the V build system to build the binaries to designated directory, doing cleanups, 
 * run an executable module or just list all modules, and that's it. All modules that is going to be 
 * included in this build driver should be added to the svbd.config
 *
 * You copy the content of this file to a V file in somewhere your $PATH / %PATH%, or you can copy the 
 * entire file to somewhere in your project. This script can be executed as a shell script file (recommended) 
 * or as a compiled to a binary.
 */


// The region folding in VSCode would require the "#region folding for VSCode" extension since v-analyzer on
// VSCode as of 04/2025 still hasn't supported code folding

// #region Main Entry

// Main Entry of the program
fn main()
{
	args := arguments()
	mut app := App{
		log: Logger{ enabled : true }
	}
	app.init_validator()

	for i := 1; i < args.len; i++
	{
		arg := args[i]

		match arg
		{
			"-h", "--help" { exit(app.print_help()) }
			"-l", "--list" { app.set_list_mode() }
			"-r", "--run" { app.set_run_mode() }
			"--clean" { app.set_cleanup_mode() }
			"-prod", "-rel", "--release", "--production" { app.set_build_type(true) }
			"-g", "--debug" { app.set_build_type(false) }
			"-f", "--force" { app.set_force_build() }
			"-os" { app.set_os(args, mut i) }
			"-v", "--verbose" { app.enable_verbosity() }
			"-vv", "--v-verbose" { app.set_v_verbose() }
			"-o", "--output" { app.set_output_dir(args, mut i) }
			else { 
				app.log.d("main", "Doesn't seems like an option, treating as a module : [argv[${i}]] ${arg}")
				app.modules << arg 
			}
		}
	}

	match true
	{
		app.is_clean_mode 
		{
			app.clean_modules()
		}

		app.is_list_mode
		{
			app.list_modules()
		}

		app.is_run_mode
		{
			app.run_module()
		}

		else 
		{
			app.build_modules()
		}
	}
}

// #endregion Main Entry
// #region Core App Data

// Core App State struct
struct App
{
mut:
	log Logger
	validator ModNameValidator

	target_os Optionals[string]
	build_type Optionals[bool]
	output_dir Optionals[string]
	exe_ext Optionals[string]
	lib_ext Optionals[string]
	is_run_mode bool
	is_forced bool
	is_v_verbose bool
	is_clean_mode bool
	is_list_mode bool

	build_info_read bool 
	build_infos []BuildInfo
	modules []string
}

fn (mut app App) list_modules()
{
	if !app.build_info_read { app.read_build_info() }
	for build_info in app.build_infos
	{
		println(build_info.str())
	}
}

fn (mut app App) run_single_module(info BuildInfo) int
{
	tag := "run_module"
	vbin := get_system_v_bin() or { app.log.fk(tag, "Cannot find V executable : ${err}") }

	if !info.folder_exists { app.log.fk(tag, "Module folder did not exists!") }
	if !info.vmod_exists { app.log.w(tag, "Module folder did not contains v.mod file, V may not happy.") }

	mut cmd := [ "" ]
	
	if app.target_os.active  { cmd << [ "-os", app.target_os.value ] }
	if app.is_v_verbose { cmd << "-v" }

	mut f_cmd := cmd.join(" ") 
	if info.flags.active { f_cmd = "${f_cmd} ${info.flags.value}" }
	return os.system("\"${vbin}\" run ${f_cmd} ${info.module_path}")
}

fn get_system_v_bin() !string
{
	return os.find_abs_path_of_executable("v")
}

fn (mut app App) run_module()
{
	if !app.build_info_read { app.read_build_info() }

	tag := "run_module"
	if app.modules.len > 0 
	{
		for mod in app.modules 
		{
			build_info := app.find_module_build_info(mod) or { 
				app.log.e(tag, "ERR: ${err}")
				continue 
			}

			if build_info.build_type == .exe 
			{
				app.log.d(tag, "Found executable module : ${build_info.name}")
				exit_code := app.run_single_module(build_info)
				exit(exit_code)
			}
		}
	} 

	app.log.fk(tag, "No module is specified to run.")
}

fn (app App) build_single_module(build_info BuildInfo)
{
	tag := "build"
	mut entries := []string{}
	os.walk_with_context(build_info.module_path, &entries, fn (mut entries []string, ent string){ entries << ent })
	bin_path := build_info.get_binary_full_path(app)

	mut src_mtime := i64(0)
	mut bin_exist := false
	mut bin_mtime := i64(0)

	for entry in entries 
	{
		m_stat := os.stat(entry) or { 
			app.log.w(tag, "Unable to stat \"${entry}\"")
			continue
		 }

		 m_mtime := m_stat.mtime
		 if m_mtime > src_mtime {
			src_mtime = m_mtime
		 }
	}

	for {
		app.make_output_dir()
		if os.exists(bin_path)
		{
			m_stat := os.stat(bin_path) or { 
				app.log.w(tag, "Unable to stat \"${bin_path}\"")
				break
			}
			bin_exist = true
			bin_mtime = m_stat.mtime
		}
		break
	}

	if !bin_exist || src_mtime > bin_mtime  || app.is_forced
	{
		vbin := get_system_v_bin() or { app.log.fk(tag, "Cannot find V executable : ${err}") }

		if !build_info.folder_exists { app.log.fk(tag, "Module folder did not exists!") }
		if !build_info.vmod_exists { app.log.w(tag, "Module folder did not contains v.mod file, V may not happy.") }

		mut cmd := [ "" ]
	
		if app.target_os.active  { cmd << [ "-os", app.target_os.value ] }
		if app.is_v_verbose { cmd << "-v" }
		if build_info.build_type == .lib { cmd << "-shared" }
		if app.build_type.active { cmd << if app.build_type.value { "-prod" } else { "-g" } }
		cmd << ["-o", bin_path]

		mut f_cmd := cmd.join(" ")

		if build_info.flags.active {
			f_cmd = "${build_info.flags} ${f_cmd}"
		}

		g_cmd := "\"${vbin}\" ${build_info.module_path} ${f_cmd}"
		app.log.d(tag, "Starting ${g_cmd}")
		exit_code := os.system(g_cmd)
		if exit_code != 0
		{
			err_msg := os.get_error_msg(exit_code)
			app.log.i(tag, "${build_info.name} - FAILED : ${err_msg}")
		}else
		{
			app.log.i(tag, "${build_info.name} - SUCCESS")
		}
	}
	else
	{
		app.log.i(tag, "${build_info.name} - UP-TO-DATE")
	}

}

fn (mut app App) build_modules()
{
	if !app.build_info_read { app.read_build_info() }
	tag := "build"

	if app.modules.len > 0 
	{
		for mod in app.modules 
		{
			app.log.i(tag, "Building module : \"${mod}\"")
			build_info := app.find_module_build_info(mod) or { 
				app.log.e(tag, "ERR: ${err}")
				continue 
			}

			app.build_single_module(build_info)

		}
	} else {
		app.log.fk(tag, "No module to build")
	}
}

fn (mut app App) clean_single_module(build_info BuildInfo)
{
	tag := "cleanup"
	file := build_info.get_binary_full_path(app)
	if os.exists(file)
	{
		app.log.d(tag, "Output binary for module \"${build_info.name}\" at \"${file}\" found, deleting...")
		os.rm(file) or {
			app.log.e("clean", "Unable to delete : ${err}")
			return
		}
		app.log.d(tag, "Output binary for module \"${build_info.name}\" at \"${file}\" deleted")
	}else
	{
		app.log.d(tag, "Output binary for module \"${build_info.name}\" at \"${file}\" did not exists, seems like nothing do~")
	}
}

fn (mut app App) clean_modules()
{
	tag := "cleanup"
	if !app.build_info_read { app.read_build_info() }

	if app.modules.len > 0 {
		app.log.d(tag, "1 or more module is specified, cleaning these modules")
		for mod in app.modules 
		{
			app.log.d(tag, "cleaning up ${mod}")
			build_info := app.find_module_build_info(mod) or { 
				app.log.e(tag, "ERR: ${err}")
				continue 
			}
			app.clean_single_module(build_info)
		}
	} else {
		app.log.d(tag, "No module is specified, cleaning all modules instead")
		for build_info in app.build_infos
		{
			app.log.d(tag, "cleaning up ${build_info.name}")
			app.clean_single_module(build_info)
		}
	}
}

const types_lib := [ "l", "lib", "library", "shared", "dll", "so", "dylib" ]
const types_exe := [ "e", "exe", "executable" ]

fn (mut app App) set_build_type(is_release bool)
{
	relmode_str := if is_release { "release" } else { "debug" }
	app.log.d("relmode", "Binary build type is set to ${relmode_str}")
	app.build_type.enable(is_release)
}

fn (mut app App) set_force_build()
{
	app.log.d("selinux", "Forced to build even on newer binary")
	app.is_forced = true
}

fn (mut app App) set_output_dir(args []string, mut i &int)
{
	tag := "outdir"
	index := i
	if args.len <= index + 1 {
		app.log.fk(tag, "target directory not specified")
	}

	output_dir := args[index+1]
	app.log.i(tag, "Target directory is set to = ${output_dir}")
	app.target_os.enable(output_dir)
	i++
}

fn (mut app App) set_cleanup_mode()
{
	app.log.d("clean_maid", "Mode is set to cleanup")
	app.is_clean_mode = true
}

fn (mut app App) set_v_verbose()
{
	app.log.d("verbose_v", "V compiler is set to verbose")
	app.is_v_verbose = true
}

fn (mut app App) set_run_mode()
{
	app.log.d("run_away", "Run mode activated, only select first specified module")
	app.is_run_mode = true
}

fn (mut app App) read_build_info()
{
	tag := "cfg_parser"
	path := os.abs_path("svbd.config")
	app.log.d(tag, "Reading svbd.config at \"${path}\"")
	if !os.exists(path)
	{
		app.log.fk(tag, "Cannot find svbd.config in current directory")
	}

	lines := os.read_lines(path) or { app.log.fk(tag, "Unable to read svbd.config : ${err}") }

	mut line_index := 0
	for line in lines
	{
		line_index++
		if line.is_blank() { 
			app.log.d(tag, "${line_index}: blank")
			continue 
		}
		if line.trim_space().starts_with("#") {  
			app.log.d(tag, "${line_index}: comment \"${line}\"")
			continue
		}

		app.log.d(tag, "${line_index}: ${line}")
		m_type := line.all_before(":").trim_space().to_lower()

		e_type := match true
		{
			types_lib.contains(m_type) { EBuildBinType.lib }
			types_exe.contains(m_type) { EBuildBinType.exe }
			else { EBuildBinType.unk }
		}

		if e_type == .unk
		{
			app.log.fk(tag, "Unknown module binary type : ${m_type}")
		}

		m_name_flag := line.all_after_first(":")
		m_name := m_name_flag.all_before("|").trim_space()
		m_flag := if m_name_flag.contains("|") { m_name_flag.all_after_first("|").trim_space() } else { "" }

		if m_name.is_blank() { app.log.fk(tag, "Module name cannot be blank!") }
		
		if app.validator.regex.find_all(m_name).len > 0 { app.log.fk(tag, "Module name must be in vlang style") }

		folder_path := os.abs_path(m_name)
		vmod_path := os.join_path(folder_path, "v.mod")

		folder_exists := os.exists(folder_path) && os.is_dir(folder_path)
		vmod_exists := os.exists(vmod_path) && os.is_file(vmod_path)

		mut o_flag := Optionals[string]{}

		if m_flag.is_blank()
		{
			app.log.d(tag, "Flag for module ${m_name} is blank")
			o_flag.disable()
		} else
		{
			app.log.d(tag, "Flag for module ${m_name} : ${m_flag}")
			o_flag.enable(m_flag)
		}

		build_info := BuildInfo {
			name: m_name,
			build_type: e_type,
			flags : o_flag,
			module_path : folder_path,
			folder_exists: folder_exists,
			vmod_exists: vmod_exists	
		}
		
		app.build_infos << build_info
	}

	app.build_info_read = true
}

fn (mut app App) set_list_mode()
{
	app.log.d("lsmod", "List all modules")
	app.is_list_mode = true
}

fn (mut app App) enable_verbosity()
{
	app.log.severity_mask.enable(.debug)
	app.log.d("args_verbose", "verbosity is set to debug")
}

fn (app App) eval_output_dir() string
{
	mut path := if app.output_dir.active { app.output_dir.value } else { "build" }
	if !os.is_abs_path(path) 
	{
		path = os.abs_path(path)
	}
	return path
}

fn (app App) make_output_dir()
{
	tag := "mk_build_dir"
	path := app.eval_output_dir()
	if !os.exists(path)
	{
		os.mkdir(path) or { app.log.fk(tag, "Unable to create output directory : ${err}") }
	} else if !os.is_dir(path)
	{
		if app.is_forced
		{
			app.log.w(tag,"Output directory exists as a file! force deleting it...")
			os.rm(path) or { app.log.fk(tag, "Unable to delete the file that is in place of output directory : {err}") }
			os.mkdir(path) or { app.log.fk(tag, "Unable to create output directory : ${err}") }
		}else
		{
			app.log.fk(tag,"Output directory exists as a file!")
		}
	}
}

fn (mut app App) set_os(args []string, mut i &int)
{
	tag := "args_os"
	index := i
	if args.len <= index+1 {
		app.log.fk(tag, "OS not specifid")
	}

	new_os := args[index+1]
	app.log.i(tag, "Found OS = ${new_os}")
	app.target_os.enable(new_os)
	i++
}

fn (_ App) print_help() int
{
	println(r"svbd - simple v build driver
usage : svbd.v [OPTIONS] [module_name...]

You can specify multiple modules to build

This script reads all of the config from 'svbd.config' in current working directory

## Options 
```
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

## About svbd.config 
### Format 
- Entries:
  Entries are formatted in [type]:[name] [| [flags...] ]
  Type is either:
  - l, lib, library, dll, so - Shared Library
  - e, exe, executable - Executable
  Name corresponds to the folder name
  Additional flags are appended to the build command on execution, please ..
  do not add file output flags, it is managed by this build system!
- Comment : 
  comments starts with # or ;
- Empty line is ignored

### Sample
```
# this is comment
e:core_game |-autofree 
l:asset_main
l:asset_dlc_1
l:asset_dlc_2
```
");
	return 1
}

// #endregion Core App Data
// #region Validator

struct ModNameValidator
{
mut:
	regex regex.RE
}

fn (mut app App) init_validator()
{
	mut module_name_regex := regex.new()
	module_name_regex.compile_opt("^[^a-zA-Z_]|[^a-zA-Z0-9_]+$") 
		or { app.log.fk("revalida", "Invalid Regex ( programmer's fault! ) - ${err}") }
	
	app.validator = ModNameValidator{ regex: module_name_regex }
}

// #endregion Validator
// #region Build Info

enum EBuildBinType
{
	unk 
	exe
	lib
}

fn get_system_lib_file_ext() string
{
	return $if linux || bsd || android {
		"so"
	} $else $if windows {
		"dll"
	} $else $if darwin {
		"dylib"
	} $else {
		"bin"
	}
}

fn get_system_exe_file_ext() string
{
	return $if linux || bsd {
		""
	} $else $if windows {
		"exe"
	} $else $if darwin {
		"app"
	} $else {
		"bin"
	}
}

fn get_system_lib_prefix_ext() string
{
	return $if linux {
		"lib"
	} $else {
		""
	}
}

fn (bin_type EBuildBinType) get_bin_extension(app App) string
{
	return match bin_type
	{
		.exe { if app.exe_ext.active { app.exe_ext.value } else { get_system_exe_file_ext() } }
		.lib { if app.lib_ext.active { app.lib_ext.value } else { get_system_lib_file_ext() } }
		else { "" }
	}
}

struct BuildInfo
{
	name string
	build_type EBuildBinType
	flags Optionals[string]

	module_path string

	folder_exists bool
	vmod_exists bool
}

fn (info BuildInfo) get_binary_full_path(app App) string
{
	ext := info.build_type.get_bin_extension(app)
	prefix := if info.build_type == .lib { get_system_lib_prefix_ext() } else { "" }
	f_name := if ext.is_blank() { info.name } else { "${prefix}${info.name}.${ext}" }
	out_dir := app.eval_output_dir()
	return os.join_path(out_dir, f_name)
}

fn (app App) find_module_build_info(name string) !BuildInfo
{
	for build_info in app.build_infos
	{
		if build_info.name == name
		{
			return build_info
		}
	}
	return error("Unable to find build info for module named ${name}")
}

fn (info BuildInfo) str() string
{
	m_type := match info.build_type
	{
		.exe { "EXECUTABLE" }
		.lib { "LIBRARY" }
		else { "???" }
	}

	diag := match false
	{
		info.folder_exists { "\tWARN: Module directory for module \"${info.name}\" not found in current directory\n" }
		info.vmod_exists { "\tWARN: v.mod file for module \"${info.name}\" not found in it's module directory\n" }
		else { "" }
	}

	return "${info.name} [${m_type}]\n${diag}"
}

// #endregion Build Info
// #region Optional 
struct Optionals[T]
{
mut:
	active bool
	value T
}

fn (mut opt Optionals[T]) just_enable() 
{
	opt.active = true
}

fn (mut opt Optionals[T]) enable(value T)
{
	opt.value = value
	opt.active = true
}

fn (mut opt Optionals[T]) disable()
{
	opt.active = false
}

// #endregion Optionals
// #region Logging
enum ELogSeverity
{
	fatal =   0b00001
	error =   0b00010
	warning = 0b00100
	info =    0b01000
	debug =   0b10000
	default = 0b01111
	all =     0b11111
}

struct Logger
{
mut:
	severity_mask ELogSeverity = .default
	enabled bool = true
}

fn (mut sev ELogSeverity) set( sv_flag ELogSeverity, enabled bool ) ELogSeverity
{
	mut isev := i32(sev)
	isvf := i32(sv_flag)
	if enabled { isev |= isvf }
	else { isev &= ~isvf }
	sev = unsafe { ELogSeverity(isev) } 
	return sev
}

fn (mut sev ELogSeverity) enable(sv_flag ELogSeverity) ELogSeverity { return sev.set(sv_flag, true) }
fn (mut sev ELogSeverity) disable(sv_flag ELogSeverity) ELogSeverity { return sev.set(sv_flag, false) }
fn (sev ELogSeverity) is_enabled(sv_flag ELogSeverity) bool
{
	isev := i32(sev)
	isvf := i32(sv_flag)
	return (isev & isvf) == isvf
}


fn log_pad_str(src_str string, len int) string
{
	slen:= src_str.len
	if slen > len { return src_str.substr(0, len) }

	diff := len - slen
	spaces := " ".repeat(diff)
	return "${src_str} ${spaces}"
}

fn (log Logger) write(sev ELogSeverity, tag string, txt string)
{
	// Log is disabled
	if !log.enabled { return }

	// This log severity is disabled
	if !log.severity_mask.is_enabled(sev) { return }
	
	sev_str := match sev
	{
		.debug { "DBG" }
		.error { "ERR" }
		.warning { "WRN" }
		.info { "INF" }
		.fatal { "FTL" }
		else { "???" }
	}

	tag_f := log_pad_str(tag, 20)
	final_str := '[${sev_str}] ${tag_f} ${txt}'
	if sev == .error {  eprintln(final_str) }
	else if sev == .fatal { error(final_str) }
	else { println(final_str) }
}

fn (log Logger) d(tag string, txt string) { log.write(.debug, tag, txt) }
fn (log Logger) e(tag string, txt string) { log.write(.error, tag, txt) }
fn (log Logger) w(tag string, txt string) { log.write(.warning, tag, txt) }
fn (log Logger) i(tag string, txt string) { log.write(.info, tag, txt) }

// This is a layer for panic, so use this only if there is any fatal error
@[noreturn]
fn (log Logger) fk(tag string, txt string) { log.write(.fatal, tag, txt); for {} }
// #endregion Logging