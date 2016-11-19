##
## BEGIN LICENSE BLOCK
##
## Copyright (C) Electric Cloud 2016 
## Author  :  Mike Bily
## END LICENSE BLOCK

#TODO:
#tcl script for WINDOWS 
#task:
#1) get argument - what folder to analyze
#2) create folder structure 
#Windows
#
#3) get list of all binaries
#4) analyze binary(exe,dll) files at folder.
#4) result - files (wiki mark up or Html) with report and statistic

#report structure : 
#     tree in folder 
#     table with summary 32-bit / 64-bit exe/dll files 

#LINUX
#3) analyze binary(so,binary) files at folder.
#4) result -  files (wiki mark up  or Html)  with report and statistic
#report structure : 
#     tree in folder 
#     table with summary 32-bit/64-bit so/binary files 


# get_arguments
#    handling command-line option
#    option should be path to the existed folder
#    return: path to file in option
#common
proc get_arguments { } {
	global argv argc ;# procedure can see global variables
	if { $argc > 0  } {
		set file_name [lindex $argv 0]
		if { [file exists $file_name ] &&  [ file isdirectory $file_name ]} {
			set path $file_name
		} else { 
			puts "Can't access to file $file_name - please check commandline first option" 
			exit 
		}		
	} else { 
		puts "expected \"tclsh analyzeVxx.tcl path\" - please try again" 
	}
	return $path  
}

# get_files_in_folder
#     get list of files in folder
#     return: list with file's names
#common
proc get_files_in_folder { path } {
	set curdir [pwd]	
	cd $path
	set files_list [glob -nocomplain -- *] 
	cd $curdir
	return $files_list
}

# is_folder
#     check path and return true if it is folder
#     full_file_name : path to folder
#     return : true if  $full_file_name is folder
#common
proc is_folder { full_file_name } {
	set is_folder_var 0
	if { [file isdirectory  $full_file_name] } {
		set is_folder_var 1
	} 
	return $is_folder_var
}

# create_lists_files_and_folders  - walking inside folders to get list of files
#     path : folder location
#     return : [list folders $folders files $files ]
#common
proc  create_lists_files_and_folders { path } {
	global gFilesPointer gFolders 
	set    root_folder $path
	lappend folders  $root_folder
	set    index 0 
	# analyze list 
	while { $index < [llength $folders] } {
		set current_item [lindex $folders $index]
		incr index
		set list_of_files_at_folder [get_files_in_folder $current_item]
		foreach file_at_current_folder $list_of_files_at_folder {
			set full_path [file join $current_item $file_at_current_folder]
			if { [ is_folder $full_path] } {
				lappend folders $full_path
			} elseif { [file isfile  $full_path] } {
				lappend files $full_path
			}
		}
		
	}
	if { ![info exists files] } { lappend files {} }
	return [list folders $folders files $files ]
}

#is_exe
#    check binary file by ext
#    file_name -
#    return: true if file has ext == exe
proc is_exe { file_name } {
	set is_exe_ 0
	set ext [file extension $file_name]
	if { [ string match ".exe" $ext]} {
		set is_exe_ 1
	}
	return $is_exe_
}

#is_dll
#    check binary file by ext
#    file_name -
#    return: true if file has ext == dll
proc is_dll { file_name } {
	set is_dll_ 0
	set ext [file extension $file_name]
	if {[string match ".dll"  $ext ]} {
		set is_dll_ 1
	}
	return $is_dll_
}

#is_lib - linux
#    check binary file by ext
#    file_name -
#    return: true if file has ext == so
#linux specific
proc is_lib { file_name } {
	set is_lib_ 0
	set ext [file extension $file_name]
    #set dirname [file dirname $file_name]
    #set dirname_lenght  [string length $dirname]
    #set filename_length [string length $file_name]
    #going get name of file 
    #set filename [string range $file_name  [expr $dirname_lenght + 1] $filename_length]
	if { [ string match ".so" $ext] ||  [regexp {.so} $file_name ]} {
		set is_lib_ 1
	}
	return $is_lib_
}

#separate_lib_binary - linux
#    sort files by ext (.so)
#    return: [list bin $_files lib $lib_files ] 
#linux specific
proc separate_lib_binary { files_list } {
    puts "debug - separate_lib_binary"
	 foreach i_file $files_list {
	 	if { [ is_lib $i_file] } {
            lappend lib_files $i_file
	 	} else {    
            lappend bin_files $i_file
        }
	 }
	 if {![info exists lib_files]} { set lib_files {} }
	 if {![info exists bin_files]} { set bin_files {} }
	return [list bin $bin_files lib $lib_files ] 
}

#separate_dll_exe - windows
#    sort files by ext (dll or exe)
#    return: [list exe $exe_files dll $dll_files ] 
proc separate_dll_exe { files_list } {
	 foreach i_file $files_list {
	 	if { [ is_exe $i_file] } {
	 		 lappend exe_files $i_file
	 	}
	 	if { [is_dll $i_file] } {
	 		 lappend dll_files $i_file
	 	}
	 	
	 }
	 if {![info exists dll_files]} { set dll_files {} }
	 if {![info exists exe_files]} { set exe_files {} }
	return [list exe $exe_files dll $dll_files ] 
}

# is_32_or_64_bit - windows
#     get bitnes of binary
#     file_name:
#     return: 32 or 64
proc is_32_or_64_bit { file_name } {
	set fid  [open $file_name r]
	set data [read $fid 10000]
	close $fid
	set index [string first "PE" $data ]
	set index_shift [expr $index + 4 ]
	set char [string range $data $index_shift $index_shift ]
	#set hex_char [binary encode   hex $char ]    ;#tcl 8,5
	binary scan  $char H* hex_char   ; # tcl 8,5
	if { [ expr { $hex_char == "4c" } ] } {
		set bit 32
	} elseif { [ expr { $hex_char == "64" } ] }  {
		set bit 64
	} else {
		set bit wrong
	}

	return $bit
}

# is_32_or_64_bit_L
#    Read Linux binary for getting bitness
#    file_name
#    return: $bit = 32 64 wrong
#linux specific
proc is_32_or_64_bit_L { file_name } {
	set file [auto_execok file ]
    catch {exec $file -e elf -b $file_name} result
    if { ! [regexp {.*ELF (\d+)-bit LSB.*} $result sting bit] } {
       set bit "wrong"     
    }
    # puts "$file_name    $bit"
	return $bit
}

# recommended by @Eric@
# is_32_or_64_bit_ -  Windows
#    Read Windows binary for getting bitness
#    file_name
#    return: $bit = 32 64 wrong
proc is_32_or_64_bit_ { file_name } {
	set magic ""
	set fid  [open $file_name r]
	fconfigure $fid -translation binary -encoding binary
	binary scan [read $fid 68] "a2a58i1" magic unused offset
	if { $magic != "MZ" } {
		set bit "wrong"
	} else {
		#puts $file_name
		seek $fid $offset
		binary scan [read $fid 6] "a2a2su1" sig unused mach
		if { $sig != "PE" } {
			#close $fid
        	set bit "wrong"
    	} else {
    		if { $mach == 0x014c || $mach == 452 } {
        		set bit "32"
    		} elseif { $mach == 0x0200 } {
        	set bit "64"
    		} elseif { $mach == 0x8664 } {
        	set bit "64"
    		} 
		}
	}
	if {![info exists bit]} { set bit "wrong" 
		puts "$mach $file_name"
	}
	close $fid
	return $bit
}


# analyze_bitnes_forWindows -  windows
#     files_list -list 
#     return: [list 32 $arr_bit(32) 64 $arr_bit(64) unknown $arr_bit(wrong) ] 
proc analyze_bitnes_forWindows { files_list} {
	array set arr_bit [list 32 {} 64 {} wrong {}]
	foreach i_file $files_list {
		set prefix [is_32_or_64_bit_ $i_file]
		lappend  arr_bit($prefix)  $i_file
	}
	return [list 32 $arr_bit(32) 64 $arr_bit(64) unknown $arr_bit(wrong) ] 
}

# common
# p_file_size
#     file_path
#     converted size   
proc p_file_size { file_path } {
	set file_size [file size $file_path]
	return [ size_convertor $file_size ]	
}

# common
proc size_convertor { byte_size } {
	set file_size $byte_size
		if { ! [ expr $file_size < 1024 ]} {
				if { [expr $file_size < 1048576 ]} {
					set file_size "[expr $file_size / 1024 ].[expr $file_size % 1024] Kb"
				} else {
					set file_size "[expr $file_size / 1048576 ].[expr $file_size % 1024 ]  Mb"
				}		
		}
		return $file_size
}


# analyze_bitnes_onLinux
#     files_list -list 
#     return: [list 32 $arr_bit(32) 64 $arr_bit(64) unknown $arr_bit(wrong) ] 
proc analyze_bitnes_onLinux { files_list} {
	array set arr_bit [list 32 {} 64 {} wrong {}]
	foreach i_file $files_list {
		set prefix [is_32_or_64_bit_L $i_file]
		lappend  arr_bit($prefix)  $i_file
	}
	#
	return [list 32 $arr_bit(32) 64 $arr_bit(64) unknown $arr_bit(wrong) ] 
}


proc wiki_markap_report {} {
	global gFilesPointer 
	set Text_before_table "Files at folder $gFilesPointer(topFolder)"
	set text_after_table "files total : [llength $gFilesPointer(files)]"
	set table_name "Table of files"
	set template_wiki [list $Text_before_table "\{| class=\"wikitable sortable collapsible\" style=\"margin: 1em auto 1em auto;\"]" \
"|+ \'\'\'$table_name\'\'\'" "! scope=\"col\" | N" "! scope=\"col\" | path"  "! scope=\"col\" | size" ]
	set cnt 0
	set param_white_red    "style=\"background: red; color: white\" |"
	set param_white_blue   "style=\"background: blue; color: white\" |"
	set param_white_green  "style=\"background: green; color: white\" |"
	set param ""
	foreach item $gFilesPointer(files) {
		set param ""
		set index  $cnt
		set file_path $item
		set file_size [file size $file_path]
		if { ! [ expr $file_size < 1024 ]} {
				if { [expr $file_size < 1024000]} {
					set file_size "[expr $file_size / 1024 ].[expr $file_size % 1024] Kb"
					set param $param_white_red 
				} else {
					set file_size "[expr $file_size / 1024000 ].[expr $file_size % 1024 ]  Mb"
					set param $param_white_green
				}		
			
		}
		#set file_size [expr [file size $file_path] / 1024 ]
		lappend template_wiki "|-"
		lappend template_wiki "| $param $index  ||  $file_path || $file_size"
		incr cnt

	}
	lappend template_wiki "|\}"
	lappend template_wiki $text_after_table
	lappend template_wiki "----"

	set Text_before_table "Folders at folder $gFilesPointer(topFolder)"
	set text_after_table "Folders total : [llength $gFilesPointer(folders)]"
	set table_name "Table of folders"
	set template_wiki [ concat $template_wiki [list $Text_before_table "\{| class=\"wikitable sortable collapsible\" style=\"margin: 1em auto 1em auto;\"]" \
	"|+ \'\'\'$table_name\'\'\'" "! scope=\"col\" | N" "! scope=\"col\" | path"   ] ]
0	set cnt 0
	set param ""
	foreach item $gFilesPointer(folders) {
		set param ""
		set index  $cnt
		set file_path $item
		lappend template_wiki "|-"
		lappend template_wiki "| $param $index  ||  $file_path "
		incr cnt

	}
	lappend template_wiki "|\}"
	lappend template_wiki $text_after_table
	lappend template_wiki "----"


	set Text_before_table "32-bit files at $gFilesPointer(topFolder)"
	set text_after_table "32-bit  binary : [expr [llength $gFilesPointer(exe_32)] + [llength $gFilesPointer(dll_32)]] \n "
	set table_name "Table of 32-bit binary"
	set template_wiki [ concat $template_wiki [list $Text_before_table "\{| class=\"wikitable sortable collapsible\" style=\"margin: 1em auto 1em auto;\"]" \
	"|+ \'\'\'$table_name\'\'\'" "! scope=\"col\" | N" "! scope=\"col\" | path" "! scope=\"col\" | size"  ] ]
	set cnt 0
	set param $param_white_red
	foreach item $gFilesPointer(exe_32) {
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend template_wiki "|-"
		lappend template_wiki "| $param $index  ||  $file_path  || $file_size"
		incr cnt

	}
	set param $param_white_blue
	foreach item $gFilesPointer(dll_32) {
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend template_wiki "|-"
		lappend template_wiki "| $param $index  ||  $file_path || $file_size"
		incr cnt

	}
	lappend template_wiki "|\}"
	lappend template_wiki $text_after_table
	lappend template_wiki "----"

	set Text_before_table "64-bit files at $gFilesPointer(topFolder)"
	set text_after_table "64-bit  binary : [expr [llength $gFilesPointer(exe_64)] + [llength $gFilesPointer(dll_64)]] \n "
	set table_name "Table of 64-bit binary"
	set template_wiki [ concat $template_wiki [list $Text_before_table "\{| class=\"wikitable sortable collapsible\" style=\"margin: 1em auto 1em auto;\"]" \
	"|+ \'\'\'$table_name\'\'\'" "! scope=\"col\" | N" "! scope=\"col\" | path" "! scope=\"col\" | size"  ] ]
	set cnt 0
	set param $param_white_red
	foreach item $gFilesPointer(exe_64) {
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend template_wiki "|-"
		lappend template_wiki "| $param $index  ||  $file_path  || $file_size"
		incr cnt

	}
	set param $param_white_blue
	foreach item $gFilesPointer(dll_64) {
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend template_wiki "|-"
		lappend template_wiki "| $param $index  ||  $file_path || $file_size"
		incr cnt

	}
	lappend template_wiki "|\}"
	lappend template_wiki $text_after_table
	lappend template_wiki "----"

	set Text_before_table "unknown binary files at $gFilesPointer(topFolder)"
	set text_after_table  "unknown  binary : [expr [llength $gFilesPointer(exe_u)] + [llength $gFilesPointer(dll_u)]] \n "
	set table_name "Table of unknown-bit binary"
	set template_wiki [ concat $template_wiki [list $Text_before_table "\{| class=\"wikitable sortable collapsible\" style=\"margin: 1em auto 1em auto;\"]" \
	"|+ \'\'\'$table_name\'\'\'" "! scope=\"col\" | N" "! scope=\"col\" | path" "! scope=\"col\" | size"  ] ]
	set cnt 0
	set param $param_white_red
	foreach item $gFilesPointer(exe_u) {
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend template_wiki "|-"
		lappend template_wiki "| $param $index  ||  $file_path  || $file_size"
		incr cnt

	}
	set param $param_white_blue
	foreach item $gFilesPointer(dll_u) {
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend template_wiki "|-"
		lappend template_wiki "| $param $index  ||  $file_path || $file_size"
		incr cnt

	}
	lappend template_wiki "|\}"
	lappend template_wiki $text_after_table
	lappend template_wiki "----"


	return $template_wiki

}

proc atlassian_wiki_markap_report {} {
	global gFilesPointer 
	set mark  "|"
	set Text_before_table "h1. Files at folder $gFilesPointer(topFolder)"
	set text_after_table "h3. files total : [llength $gFilesPointer(files)]"
	set table_name "h4. Table of files"
	lappend template_wiki  $Text_before_table "\{table-plus:columnTypes=S,-,.|autoNumber=true|sortColumn=3 
|columnAttributes=,,style=\"background:yellow; font-size:14pt;\"\} "  \
 "|| Num || Path || file size ||" 
	set cnt 0
	foreach item $gFilesPointer(files) {
		set index  $cnt
		set file_path $item
		#set file_size [file size $file_path]
		set file_size [p_file_size  $file_path]
		lappend template_wiki "| $index  |  $file_path | $file_size |"
		incr cnt

	}
	lappend template_wiki "{table-plus} "
	lappend template_wiki $text_after_table
	lappend template_wiki "----"

	set Text_before_table "Folders at folder $gFilesPointer(topFolder)"
	set text_after_table "Folders total : [llength $gFilesPointer(folders)]"
	set table_name "Table of folders"
	lappend template_wiki  $Text_before_table "\{table-plus:columnTypes=S,-,.|autoNumber=true|sortColumn=3 
		|columnAttributes=,,style=\"background:yellow; font-size:14pt\;\"\} "  \
	 "|| Num || Path || file size ||" 
	foreach item $gFilesPointer(folders) {
		set file_path $item
		lappend template_wiki "|  $file_path |"
	}
	lappend template_wiki "{table-plus} "
	lappend template_wiki $text_after_table
	lappend template_wiki "----"


	set Text_before_table "32-bit files at $gFilesPointer(topFolder)"
	set text_after_table "32-bit  binary : [expr [llength $gFilesPointer(exe_32)] + [llength $gFilesPointer(dll_32)]] \n "
	set table_name "Table of 32-bit binary"
	lappend template_wiki [list $Text_before_table "{table-plus:columnTypes=S,-,.|autoNumber=true|sortColumn=2 
	|columnAttributes=,,style=\"background:yellow; font-size:14pt;\"}"  "|| Path || file size ||"]
	foreach item $gFilesPointer(exe_32) {
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend template_wiki "|  $file_path | $file_size |"	

	}
	
	foreach item $gFilesPointer(dll_32) {
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend template_wiki "|  $file_path | $file_size |"

	}
	lappend template_wiki "{table-plus} "
	lappend template_wiki $text_after_table
	lappend template_wiki "----"

	set Text_before_table "64-bit files at $gFilesPointer(topFolder)"
	set text_after_table "64-bit  binary : [expr [llength $gFilesPointer(exe_64)] + [llength $gFilesPointer(dll_64)]] \n "
	set table_name "Table of 64-bit binary"
	lappend template_wiki  $Text_before_table "\{table-plus:columnTypes=S,-,.|autoNumber=true|sortColumn=2 
	|columnAttributes=,,style=\"background:yellow; font-size:14pt;\"\} " \
	"|| Path || file size ||"
	foreach item $gFilesPointer(exe_64) {
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend template_wiki "|  $file_path | $file_size |"

	}
	foreach item $gFilesPointer(dll_64) {
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend template_wiki "|  $file_path | $file_size |"

	}
	lappend template_wiki "{table-plus} "
	lappend template_wiki $text_after_table
	lappend template_wiki "----"

	set Text_before_table "unknown binary files at $gFilesPointer(topFolder)"
	set text_after_table  "unknown  binary : [expr [llength $gFilesPointer(exe_u)] + [llength $gFilesPointer(dll_u)]] \n "
	set table_name "Table of unknown-bit binary"
	lappend template_wiki $Text_before_table "\{table-plus:columnTypes=S,-,.|autoNumber=true|sortColumn=2 
	|columnAttributes=,,style=\"background:yellow; font-size:14pt;\"\} " "|| Path || file size ||"
	foreach item $gFilesPointer(exe_u) {
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend template_wiki "|  $file_path | $file_size |"

	}
	foreach item $gFilesPointer(dll_u) {
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend template_wiki "|  $file_path | $file_size |"

	}
	lappend template_wiki "{table-plus} "  $text_after_table "----"
	return $template_wiki

}

proc list_to_file_wmr { list_data folder } {
	set time [clock format [clock seconds] -format "%Y-%m-%d-%H-%M-%S"]
	append file_name $folder "/wiki_report_" $time ".wmr"
	
	set fid [open  $file_name  w]
	foreach i  $list_data  {
		puts $fid $i
	}
	close $fid

}

# list_to_file_html 
#    write list data to file with html ext
#common
proc list_to_file_html { list_data folder } {
	set time [clock format [clock seconds] -format "%Y-%m-%d-%H-%M-%S"]
	append file_name  $folder "/html_report_" $time ".html"
	set fid [open   $file_name  w]
	foreach i  $list_data  {
		puts $fid $i
	}
	close $fid
}

#common
proc gathering_info {} {
	global tcl_precision
	set tcl_precision_ $tcl_precision 
	set tcl_precision 8

	global gFilesPointer 
	set file_size 0
	foreach item $gFilesPointer(exe_32) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(size_32_exe) $file_size

	set file_size 0
	foreach item $gFilesPointer(exe_64) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(size_64_exe) $file_size

	set file_size 0
	foreach item $gFilesPointer(dll_64) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(size_64_dll) $file_size

	set file_size 0
	foreach item $gFilesPointer(dll_32) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(size_32_dll) $file_size

	set file_size 0
	foreach item $gFilesPointer(dll_u) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(size_u_dll) $file_size

	set file_size 0
	foreach item $gFilesPointer(exe_u) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(size_u_exe) $file_size
	
	set file_size 0
	foreach item $gFilesPointer(files) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(all_files_size) $file_size
	set gFilesPointer(dll,size)  [expr $gFilesPointer(size_32_dll) + $gFilesPointer(size_64_dll)]
	set gFilesPointer(dll,count) [ expr [llength $gFilesPointer(dll_32)] + [llength $gFilesPointer(dll_64)]] 
	
	set gFilesPointer(exe,size) [expr $gFilesPointer(size_32_exe) + $gFilesPointer(size_64_exe)]
	set gFilesPointer(exe,count) [ expr [llength $gFilesPointer(exe_32)] + [llength $gFilesPointer(exe_64)]] 

	set gFilesPointer(exe,percent_of_total) [expr ($gFilesPointer(exe,size)*100.000) / $gFilesPointer(all_files_size)]  
	set gFilesPointer(dll_32,count) [llength $gFilesPointer(dll_32)]
		
	set gFilesPointer(dll_64,count) [llength $gFilesPointer(dll_64)]
	set gFilesPointer(exe_32,count) [llength $gFilesPointer(exe_32)]
	set gFilesPointer(exe_32,percent_of_total) [expr ($gFilesPointer(size_32_exe)*100.000) / $gFilesPointer(all_files_size)] 
	set gFilesPointer(exe_64,count) [llength $gFilesPointer(exe_64)]
	
	set gFilesPointer(exe_u,count) [llength $gFilesPointer(exe_u)]
	set gFilesPointer(exe_u,percent_of_total) [expr ($gFilesPointer(size_u_exe)*100.000) / $gFilesPointer(all_files_size)]  

	set gFilesPointer(dll_u,count) [llength $gFilesPointer(dll_u)]

	set gFilesPointer(dll,percent_of_total) [expr ($gFilesPointer(dll,size)*100.) / $gFilesPointer(all_files_size)]  
	set gFilesPointer(dll_u,percent_of_total) [expr ($gFilesPointer(size_u_dll)*100.000) / $gFilesPointer(all_files_size)]
	set gFilesPointer(exe_64,percent_of_total) [expr ($gFilesPointer(size_64_exe)*100.000) / $gFilesPointer(all_files_size)] 
	set gFilesPointer(dll_64,percent_of_total) [expr ($gFilesPointer(size_64_dll)*100.000) / $gFilesPointer(all_files_size)]  
	set gFilesPointer(dll_32,percent_of_total) [expr ($gFilesPointer(size_32_dll)*100.000) / $gFilesPointer(all_files_size)] 
	set tcl_precision $tcl_precision_
}

# gathering_info_lin
proc gathering_info_lin {} {
	global tcl_precision
	set tcl_precision_ $tcl_precision 
	set tcl_precision 8

	global gFilesPointer 
	set file_size 0
	foreach item $gFilesPointer(bin_32) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(size_32_bin) $file_size

	set file_size 0
	foreach item $gFilesPointer(bin_64) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(size_64_bin) $file_size

	set file_size 0
	foreach item $gFilesPointer(lib_64) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(size_64_lib) $file_size

	set file_size 0
	foreach item $gFilesPointer(lib_32) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(size_32_lib) $file_size

	set file_size 0
	foreach item $gFilesPointer(lib_u) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(size_u_lib) $file_size

	set file_size 0
	foreach item $gFilesPointer(bin_u) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(size_u_bin) $file_size
	
	set file_size 0
	foreach item $gFilesPointer(files) {
		set file_size [expr $file_size + [file size $item] ]
	}
	set gFilesPointer(all_files_size) $file_size
	set gFilesPointer(lib,size)  [expr $gFilesPointer(size_32_lib) + $gFilesPointer(size_64_lib)]
	set gFilesPointer(lib,count) [ expr [llength $gFilesPointer(lib_32)] + [llength $gFilesPointer(lib_64)]] 
	
	set gFilesPointer(bin,size) [expr $gFilesPointer(size_32_bin) + $gFilesPointer(size_64_bin)]
	set gFilesPointer(bin,count) [ expr [llength $gFilesPointer(bin_32)] + [llength $gFilesPointer(bin_64)]] 

	set gFilesPointer(bin,percent_of_total) [expr ($gFilesPointer(bin,size)*100.000) / $gFilesPointer(all_files_size)]  
	set gFilesPointer(lib_32,count) [llength $gFilesPointer(lib_32)]
		
	set gFilesPointer(lib_64,count) [llength $gFilesPointer(lib_64)]
	set gFilesPointer(bin_32,count) [llength $gFilesPointer(bin_32)]
	set gFilesPointer(bin_32,percent_of_total) [expr ($gFilesPointer(size_32_bin)*100.000) / $gFilesPointer(all_files_size)] 
	set gFilesPointer(bin_64,count) [llength $gFilesPointer(bin_64)]
	
	set gFilesPointer(bin_u,count) [llength $gFilesPointer(bin_u)]
	set gFilesPointer(bin_u,percent_of_total) [expr ($gFilesPointer(size_u_bin)*100.000) / $gFilesPointer(all_files_size)]  

	set gFilesPointer(lib_u,count) [llength $gFilesPointer(lib_u)]

	set gFilesPointer(lib,percent_of_total) [expr ($gFilesPointer(lib,size)*100.) / $gFilesPointer(all_files_size)]  
	set gFilesPointer(lib_u,percent_of_total) [expr ($gFilesPointer(size_u_lib)*100.000) / $gFilesPointer(all_files_size)]
	set gFilesPointer(bin_64,percent_of_total) [expr ($gFilesPointer(size_64_bin)*100.000) / $gFilesPointer(all_files_size)] 
	set gFilesPointer(lib_64,percent_of_total) [expr ($gFilesPointer(size_64_lib)*100.000) / $gFilesPointer(all_files_size)]  
	set gFilesPointer(lib_32,percent_of_total) [expr ($gFilesPointer(size_32_lib)*100.000) / $gFilesPointer(all_files_size)] 
	set tcl_precision $tcl_precision_
}

proc html_report {} {
	global gFilesPointer 
	lappend html_list "<!DOCTYPE HTML>" "<html>" "<head>" "<title> \"table of contents\"</title>"   \
	"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">" \
    "<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/1.7.2/jquery.min.js\"></script>" \
    "</head>" "<body>"  
    #files -----
   
   	#statistic-table -----
	set Text_before_table "Statistic information about files from : $gFilesPointer(topFolder)"
	set text_after_table "Finished at [clock format [clock seconds] -format \"%Y-%m-%d/%H:%M:%S\"]"
	set table_name "Table of statistic information"
	
	set cnt 0
	lappend html_list    "<div class=\"col_able\">" <a title=\"$table_name\" href=\"javascript://\">$Text_before_table</a> \
	 {<table border="1">}  <caption>$table_name</caption> <tr> {<th>N</th>} {<th>Position</th>} {<th>Size</th>} {<th>Count</th>} {<th> % of total file size</th> </tr>}
	set file_size 0
		
	set index 0
	incr index 
	
	lappend html_list "<tr>" "<td> $index</td>" "<td>dll files</td>" "<td>[size_convertor $gFilesPointer(dll,size)]</td>" "<td>$gFilesPointer(dll,count) </td>" "<td>  $gFilesPointer(dll,percent_of_total)  </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>exe files</td>" "<td>[size_convertor $gFilesPointer(exe,size)]</td>" "<td>$gFilesPointer(exe,count) </td>" "<td>  $gFilesPointer(exe,percent_of_total) </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>dll_32_bit</td>" "<td>[size_convertor $gFilesPointer(size_32_dll)]</td>" "<td>$gFilesPointer(dll_32,count)</td>" "<td>$gFilesPointer(dll_32,percent_of_total)  </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>dll_64_bit</td>" "<td>[size_convertor $gFilesPointer(size_64_dll)]</td>" "<td>$gFilesPointer(dll_64,count)</td>" "<td> $gFilesPointer(dll_64,percent_of_total) </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>exe_32_bit</td>" "<td>[size_convertor  $gFilesPointer(size_32_exe)]</td>" "<td>$gFilesPointer(exe_32,count)</td>"  "<td> $gFilesPointer(exe_32,percent_of_total) </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>exe_64_bit</td>" "<td>[size_convertor  $gFilesPointer(size_64_exe)]</td>" "<td>$gFilesPointer(exe_64,count)</td>" "<td> $gFilesPointer(exe_64,percent_of_total)  </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>dll_unknown_bit</td>" "<td>[size_convertor  $gFilesPointer(size_u_dll)]</td>" "<td>$gFilesPointer(dll_u,count)</td>" "<td> $gFilesPointer(dll_u,percent_of_total)  </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>exe_unknown_bit</td>" "<td>[size_convertor  $gFilesPointer(size_u_exe)]</td>" "<td>$gFilesPointer(exe_u,count)</td>" "<td> $gFilesPointer(exe_u,percent_of_total)  </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>all_files_at_folder</td>" "<td>[size_convertor $gFilesPointer(all_files_size)]</td>" "<td>[llength $gFilesPointer(files)]</td>" "<td> 100</td>" "</tr>"
				
	lappend html_list "</table>" $text_after_table "</div>"
	lappend html_list "<br>----"
	#end -----
	#
	#end -----
	#
	set lbin32in64 [htmp_table_comp $gFilesPointer(exe_32) $gFilesPointer(exe_64) exe]
	
	set html_list  [ concat  $html_list $lbin32in64]
	lappend html_list "<br>----"
	#end -----
	set llib32in64 [htmp_table_comp $gFilesPointer(dll_32) $gFilesPointer(dll_64) dll]
	
	set html_list  [ concat  $html_list $llib32in64]
	lappend html_list "<br>----"
	#end -----
	#
	
	#32-bit -----
	set Text_before_table "32-bit files at $gFilesPointer(topFolder)"
	set text_after_table "32-bit  binary : [expr [llength $gFilesPointer(exe_32)] + [llength $gFilesPointer(dll_32)]] \n "
	set table_name "Table of 32-bit binary"
	
	set cnt 0
	set html_list [concat  $html_list [list "<div class=\"col_able\">" \
	 "<a title=\"$table_name \" href=\"javascript://\">$Text_before_table</a>" \
	 "<table border=\"1\">"  "<caption>$table_name</caption>" <tr> <th>N</th> <th>Path</th> <th>Size</th> </tr>]]
	foreach item $gFilesPointer(exe_32) {
		#set param ""
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}
	foreach item $gFilesPointer(dll_32) {
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}
	lappend html_list "</table>" $text_after_table "</div>"
	lappend html_list "<br>----"
	#end -----
	#64-bit -----
	set Text_before_table "64-bit files at $gFilesPointer(topFolder)"
	set text_after_table "64-bit  binary : [expr [llength $gFilesPointer(exe_64)] + [llength $gFilesPointer(dll_64)]] \n "
	set table_name "Table of 64-bit binary"
	
	set cnt 0
	set html_list [concat  $html_list [list "<div class=\"col_able\">" \
	 "<a title=\"$table_name \" href=\"javascript://\">$Text_before_table</a>" \
	 "<table border=\"1\">"  "<caption>$table_name</caption>" <tr> <th>N</th> <th>Path</th> <th>Size</th> </tr>]]
	foreach item $gFilesPointer(exe_64) {
		#set param ""
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}

	foreach item $gFilesPointer(dll_64) {
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}
	lappend html_list "</table>" $text_after_table "</div>"
	lappend html_list "<br>----"
	#end -----
	#unknown-bit-binary -----

	set Text_before_table "Unknown-bit binary at $gFilesPointer(topFolder)"
	set text_after_table "Unknown-bit binary: [expr [llength $gFilesPointer(exe_u)] + [llength $gFilesPointer(dll_u)]] \n "
	set table_name "Table of Unknown-bit binary"
	
	set cnt 0
	set html_list [concat  $html_list [list "<div class=\"col_able\">" \
	 "<a title=\"$table_name \" href=\"javascript://\">$Text_before_table</a>" \
	 "<table border=\"1\">"  "<caption>$table_name</caption>" <tr> <th>N</th> <th>Path</th> <th>Size</th> </tr>]]
	foreach item $gFilesPointer(exe_u) {
		#set param ""
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}
	foreach item $gFilesPointer(dll_u) {
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}
	lappend html_list "</table>" $text_after_table "</div>"
	lappend html_list "<br>----"
	#end -----
	
	set Text_before_table "Files at folder $gFilesPointer(topFolder)"
	set text_after_table "files total : [llength $gFilesPointer(files)]"
	set table_name "Table of files"
	
	set cnt 0
	lappend html_list   {<div class="col_able">} "<a title=\"$table_name \" href=\"javascript://\">$Text_before_table</a>" \
	 {<table border="1">}  "<caption>$table_name</caption>" {<tr> <th>N</th> <th>Path</th> <th>Size</th> </tr>}
	foreach item $gFilesPointer(files) {
		#set param ""
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}
	lappend html_list "</table>" $text_after_table "</div>"
	lappend html_list "<br>----"
	#end -----
	#folders -----
	set Text_before_table "Folders at folder : $gFilesPointer(topFolder)"
	set text_after_table "count of folders   : [llength $gFilesPointer(folders)]"
	set table_name "Table of folders"
	
	set cnt 0
	lappend html_list "<div class=\"col_able\">"  "<a title=\"$table_name\" href=\"javascript://\">$Text_before_table</a>" \
	 {<table border=\"1\">}  "<caption>$table_name</caption>" <tr> <th>N</th> <th>Path</th>  </tr>
	foreach item $gFilesPointer(folders) {
		#set param ""
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>"  "</tr>"
		incr cnt
	}
	lappend html_list "</table>" $text_after_table "</div>"
	lappend html_list "<br>----"
	#end -----

	set jscript	"<script type=\"text/javascript\">
		\$(document).ready(function() {
		\$(\"div.col_able table\").hide();
		\$(\"div.col_able>a\").each(function(){
		        \$(this).click(function(){   
		            \$(this).closest('div').find(\"table\").toggle();
		            return false;
		        });
		    });
		});
		</script> "	

	lappend html_list $jscript "</body>" "</html>"
 	return $html_list
}

proc separate_file_folder { full_path} {
	set dirname [file dirname $full_path]
    set dirname_lenght  [string length $dirname]
    set filename_length [string length $full_path]
    #going get name of file 
    set filename [string range $full_path  [expr $dirname_lenght + 1] $filename_length]
	return [list $dirname $filename  ]
}
    

# compare_32names64
#     compare files names from different lists
#     bit32 - list of 32 bit files
#     bit64 - list of 64 bit files
#     
proc compare_32names64 { bit32 bit64  } {
	#puts $bit32
	#puts $bit64
	
	set aBit32(full_path) $bit32
	#  aBit32(dir)
	#  aBit32(file)
	#  aBit32(compwith64)
	#  
	set aBit64(full_path) $bit64
	#  aBit64(dir)
	#  aBit64(file)
	#  aBit64(compwith32)
	foreach elem {32 64} {
		set lsts_folder_file [list "" ""]
		set arrName  [join [ list  aBit $elem (full_path)] ""]
		set arrName_d  [join [ list  aBit $elem (dir)] ""]
		set arrName_f  [join [ list  aBit $elem (file)] ""]
		foreach item  [set $arrName ] {
			# list with 2  items - 1 folder 2 file name 
			set  lsts_folder_file [separate_file_folder $item]
			lappend  $arrName_d [lindex $lsts_folder_file 0]
			lappend  $arrName_f [lindex $lsts_folder_file 1]
		}
	}
	unset elem arrName arrName_d arrName_f item  lsts_folder_file
	#puts "Files 32 bit - count is  :[llength $aBit32(file)]  :-----------------------------------------------------"
	#puts $aBit32(file)
	#puts "-----------------------------------------------------"
	#puts "Files 64 bit - count is  :[llength $aBit64(file)] : -----------------------------------------------------"
	#puts $aBit64(file)
	
	set aBit32(compwith64) [list]
	#set aBit32(notmutchedin64) [list]
	foreach itemf $aBit32(file) {
		set indexes ""
		set indexes [lsearch -all $aBit64(file) $itemf]
		#puts $indexies
		lappend aBit32(compwith64)   $indexes
	}
	
	#puts "-----give index of compared 32 in 64 "
	#puts $aBit32(compwith64)
	
	#puts "-----give index of not matched"
	#puts $aBit32(notmutchedin64)
	set aBit64(compwith32) [list]
	foreach itemf $aBit64(file) {
		set indexes ""
		set indexes [lsearch -all $aBit32(file) $itemf]
		#puts $indexies
		lappend aBit64(compwith32)   $indexes
	}
	#puts "-----give index of compared 64 in32 "
	#puts $aBit64(compwith32)
	return [ list comparedwith64 $aBit32(compwith64) files32 $aBit32(file) ]
	#structure
	#  list comparedwith64 LIST files32 LIST ]
}

proc htmp_table_comp { lFiles32 lFiles64  binaryName } {
	#global $strVarHtmlTable
	array set aCompareResult [ compare_32names64 $lFiles32 $lFiles64]
	#puts [array names  aCompareResult]
	set lHtmlTable [list]
	set strTextBeforeTable "Diff by names 32bit & 64bit $binaryName "
	set strTableName "Compare 32bit $binaryName & 64bit $binaryName"
	set strAfterTable $binaryName
	
	lappend lHtmlTable    "<div class=\"col_able\">" "<a title=\"$strTableName\" href=\"javascript://\">$strTextBeforeTable</a>" \
	"<table border=\"1\">"  "<caption>$strTableName</caption>" "<tr>" "<th>N</th>" "<th>32-bit binary name</th>" "<th>matched with 64-bit binary </th>" "</tr>"
	#lappend lHtmlTable <td>
	set cnt 0
	# "<tr>" "<td> $index</td>" "<td>binary name </td>" "<td>matched</td>" "</tr>"
	foreach item  $aCompareResult(files32) {
		set lIndices  [lindex $aCompareResult(comparedwith64) $cnt]
		unset -nocomplain matched
		set color ""
		if {[llength $lIndices ] > 0} {
			foreach i $lIndices {
				lappend matched "[lindex $lFiles64 $i]"
			}
			set matched [join $matched " "]
		} else {
			set matched "notMatched"
			set color  "bgcolor=\"\#FF0000\""
		}
		lappend lHtmlTable "<tr $color>" "<td> [expr $cnt + 1] </td>" \
		"<td>$item</td>" "<td>$matched</td>" "</tr>"
		incr cnt
	}
	lappend lHtmlTable "</table>" $strAfterTable "</div>"
	return $lHtmlTable
} 


proc html_report_lin {} {
	global gFilesPointer 
	lappend html_list "<!DOCTYPE HTML>" "<html>" "<head>" "<title> \"table of contents\"</title>"   \
	"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">" \
    "<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/1.7.2/jquery.min.js\"></script>" \
    "</head>" "<body>"  
    #files -----
   	#statistic-table -----
	set Text_before_table "Statistic information for files from : $gFilesPointer(topFolder)"
	set text_after_table "Finished at [clock format [clock seconds] -format \"%Y-%m-%d/%H:%M:%S\"]"
	set table_name "Table with statistic information"
	
	set cnt 0
	lappend html_list    "<div class=\"col_able\">" <a title=\"$table_name\" href=\"javascript://\">$Text_before_table</a> \
	{<table border="1">}  <caption>$table_name</caption> <tr> {<th>N</th>} {<th>Position</th>} {<th>Size</th>} {<th>Count</th>} {<th> % of total file size</th> </tr>}
	set file_size 0
	
	set index 0
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>lib files</td>" "<td>[size_convertor $gFilesPointer(lib,size)]</td>" "<td>$gFilesPointer(lib,count) </td>" "<td>  $gFilesPointer(lib,percent_of_total)  </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>executable (see bin) files</td>" "<td>[size_convertor $gFilesPointer(bin,size)]</td>" "<td>$gFilesPointer(bin,count) </td>" "<td>  $gFilesPointer(bin,percent_of_total) </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>lib_32_bit</td>" "<td>[size_convertor $gFilesPointer(size_32_lib)]</td>" "<td>$gFilesPointer(lib_32,count)</td>" "<td>$gFilesPointer(lib_32,percent_of_total)  </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>lib_64_bit</td>" "<td>[size_convertor $gFilesPointer(size_64_lib)]</td>" "<td>$gFilesPointer(lib_64,count)</td>" "<td> $gFilesPointer(lib_64,percent_of_total) </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>bin_32_bit</td>" "<td>[size_convertor  $gFilesPointer(size_32_bin)]</td>" "<td>$gFilesPointer(bin_32,count)</td>"  "<td> $gFilesPointer(bin_32,percent_of_total) </td>" "</tr>"
	incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>bin_64_bit</td>" "<td>[size_convertor  $gFilesPointer(size_64_bin)]</td>" "<td>$gFilesPointer(bin_64,count)</td>" "<td> $gFilesPointer(bin_64,percent_of_total)  </td>" "</tr>"
	incr index 
	#lappend html_list "<tr>" "<td> $index</td>" "<td>lib_unknown_bit</td>" "<td>[size_convertor  $gFilesPointer(size_u_lib)]</td>" "<td>$gFilesPointer(lib_u,count)</td>" "<td> $gFilesPointer(lib_u,percent_of_total)  </td>" "</tr>"
	#incr index 
	#lappend html_list "<tr>" "<td> $index</td>" "<td>bin_unknown_bit</td>" "<td>[size_convertor  $gFilesPointer(size_u_bin)]</td>" "<td>$gFilesPointer(bin_u,count)</td>" "<td> $gFilesPointer(bin_u,percent_of_total)  </td>" "</tr>"
	#incr index 
	lappend html_list "<tr>" "<td> $index</td>" "<td>all_files_at_folder</td>" "<td>[size_convertor $gFilesPointer(all_files_size)]</td>" "<td>[llength $gFilesPointer(files)]</td>" "<td> 100</td>" "</tr>"
				
	lappend html_list "</table>" $text_after_table "</div>"
	lappend html_list "<br>----"
	#end -----
	#
	set lbin32in64 [htmp_table_comp $gFilesPointer(bin_32) $gFilesPointer(bin_64) linux-binary]
	set html_list  [ concat  $html_list $lbin32in64]
	lappend html_list "<br>----"
	#end -----
	set llib32in64 [htmp_table_comp $gFilesPointer(lib_32) $gFilesPointer(lib_64) linux-lib]
	set html_list  [ concat  $html_list $llib32in64]
	lappend html_list "<br>----"
	#end -----
	
	#32-bit -----
	set Text_before_table "32-bit files at $gFilesPointer(topFolder)"
	set text_after_table "32-bit  binary : [expr [llength $gFilesPointer(bin_32)] + [llength $gFilesPointer(lib_32)]] \n "
	set table_name "Table of 32-bit binary"
	
	set cnt 0
	set html_list [concat  $html_list [list "<div class=\"col_able\">" \
	 "<a title=\"$table_name \" href=\"javascript://\">$Text_before_table</a>" \
	 "<table border=\"1\">"  "<caption>$table_name</caption>" <tr> <th>N</th> <th>Path</th> <th>Size</th> </tr>]]
	foreach item $gFilesPointer(bin_32) {
		#set param ""
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}
	foreach item $gFilesPointer(lib_32) {
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}
	lappend html_list "</table>" $text_after_table "</div>"
	lappend html_list "<br>----"
	#end -----
	#64-bit -----
	set Text_before_table "64-bit files at $gFilesPointer(topFolder)"
	set text_after_table "64-bit  binary : [expr [llength $gFilesPointer(bin_64)] + [llength $gFilesPointer(lib_64)]] \n "
	set table_name "Table of 64-bit binary"
	
	set cnt 0
	set html_list [concat  $html_list [list "<div class=\"col_able\">" \
	 "<a title=\"$table_name \" href=\"javascript://\">$Text_before_table</a>" \
	 "<table border=\"1\">"  "<caption>$table_name</caption>" <tr> <th>N</th> <th>Path</th> <th>Size</th> </tr>]]
	foreach item $gFilesPointer(bin_64) {
		#set param ""
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}

	foreach item $gFilesPointer(lib_64) {
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}
	lappend html_list "</table>" $text_after_table "</div>"
	lappend html_list "<br>----"
	#end -----
	#unknown-bit-binary -----
    	
	
	set Text_before_table "Not binary files - $gFilesPointer(topFolder)"
	set text_after_table "Not binary files: [expr [llength $gFilesPointer(bin_u)] + [llength $gFilesPointer(lib_u)]] \n "
	set table_name "Table of Not-binary files"
	
	set cnt 0
	set html_list [concat  $html_list [list "<div class=\"col_able\">" \
	 "<a title=\"$table_name \" href=\"javascript://\">$Text_before_table</a>" \
	 "<table border=\"1\">"  "<caption>$table_name</caption>" <tr> <th>N</th> <th>Path</th> <th>Size</th> </tr>]]
	foreach item $gFilesPointer(bin_u) {
		#set param ""
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}
	foreach item $gFilesPointer(lib_u) {
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}
	lappend html_list "</table>" $text_after_table "</div>"
	lappend html_list "<br>----"
	#end -----
	
	set Text_before_table "All Files at folder - $gFilesPointer(topFolder)"
	set text_after_table "files total : [llength $gFilesPointer(files)]"
	set table_name "Table of files"
	
	set cnt 0
	lappend html_list   {<div class="col_able">} "<a title=\"$table_name \" href=\"javascript://\">$Text_before_table</a>" \
	 {<table border="1">}  "<caption>$table_name</caption>" {<tr> <th>N</th> <th>Path</th> <th>Size</th> </tr>}
	foreach item $gFilesPointer(files) {
		#set param ""
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>" "<td>$file_size</td>" "</tr>"
		incr cnt
	}
	lappend html_list "</table>" $text_after_table "</div>"
	lappend html_list "<br>----"
	#end -----
	#folders -----
	set Text_before_table "All Folders at folder : $gFilesPointer(topFolder)"
	set text_after_table "count of folders : [llength $gFilesPointer(folders)]"
	set table_name "Table of  folders"
	
	set cnt 0
	lappend html_list "<div class=\"col_able\">"  "<a title=\"$table_name\" href=\"javascript://\">$Text_before_table</a>" \
	 {<table border=\"1\">}  "<caption>$table_name</caption>" <tr> <th>N</th> <th>Path</th>  </tr>
	foreach item $gFilesPointer(folders) {
		#set param ""
		set index  $cnt
		set file_path $item
		set file_size [p_file_size $file_path]
		lappend html_list "<tr>" "<td> $index</td>" "<td>$file_path</td>"  "</tr>"
		incr cnt
	}
	lappend html_list "</table>" $text_after_table "</div>"
	lappend html_list "<br>----"
	#end -----

	set jscript	"<script type=\"text/javascript\">
		\$(document).ready(function() {
		\$(\"div.col_able table\").hide();
		\$(\"div.col_able>a\").each(function(){
		        \$(this).click(function(){   
		            \$(this).closest('div').find(\"table\").toggle();
		            return false;
		        });
		    });
		});
		</script> "	

	lappend html_list $jscript "</body>" "</html>"
 	return $html_list
}

proc main {} {
	global os tcl_platform
	if { $tcl_platform(platform) == "windows" } {
		set os "windows"
        puts "Windows OS"
	} elseif {$tcl_platform(os) == "Linux" } {
		set os "linux"
        puts "Linux OS" 
		set file [auto_execok file ]
		if { ![file  exists $file] } {
				puts "There is no file app. on Linux platform."
				exit
		}
	} else {
		puts "Unsupported OS"
		exit
	}
	global gFilesPointer gFolder_top
	set gFolder_top [get_arguments]
	set gFilesPointer(topFolder) $gFolder_top
	puts " Start at: [clock format [clock seconds] -format "%Y-%m-%d/%H:%M:%S"]"
	set multiple_list 0 
	set multiple_list [create_lists_files_and_folders $gFolder_top]
	puts "Done 1 : Ready with files and folders"
	set gFilesPointer([lindex $multiple_list 0]) [lindex $multiple_list 1]
	set gFilesPointer([lindex $multiple_list 2]) [lindex $multiple_list 3]
    #gFilesPointer(folder) - contains list of folders
    #gFilesPointer(file) - contains list of files
	#puts "array keys :[array names gFilesPointer]"
    # clear multiple_list
	set multiple_list 0
    #if { $os == "windows" } { } else {}
    if { $os == "windows" } {
        set multiple_list [separate_dll_exe $gFilesPointer(files)]
		puts "Done 2 : Separating dlls 32 and 64 "
        set gFilesPointer([lindex $multiple_list 0]) [lindex $multiple_list 1]
	    set gFilesPointer([lindex $multiple_list 2]) [lindex $multiple_list 3]
        set multiple_list 0
        set multiple_list [analyze_bitnes_forWindows $gFilesPointer(exe)]
        #puts "[lindex $multiple_list 0] [lindex $multiple_list 2] [lindex $multiple_list 4]"
		#
		puts "Done 3 : Separating exe 32 and 64 "
        set gFilesPointer(exe_32) [lindex $multiple_list 1]
    	set gFilesPointer(exe_64) [lindex $multiple_list 3]
        set gFilesPointer(exe_u) [lindex $multiple_list 5]
		
		#compare_32names64 $gFilesPointer(exe_32)  $gFilesPointer(exe_64)
				
    	#puts "---array keys :[array names gFilesPointer]---"
    	set multiple_list 0 
    	set multiple_list [analyze_bitnes_forWindows $gFilesPointer(dll)]
    	#puts "[lindex $multiple_list 0] [lindex $multiple_list 2] [lindex $multiple_list 4]"
        set gFilesPointer(dll_32) [lindex $multiple_list 1]
    	set gFilesPointer(dll_64) [lindex $multiple_list 3]
    	set gFilesPointer(dll_u)  [lindex $multiple_list 5]
		#compare_32names64 $gFilesPointer(dll_32)  $gFilesPointer(dll_64)
    	gathering_info
		puts "Done 4 : Size counting "
    	#list_to_file_wmr  [ wiki_markap_report ] $new_dir_name
    	
    } 
    if { $os == "linux" } {
        puts "Processing separate_lib_binary" 
        set multiple_list [separate_lib_binary $gFilesPointer(files)]
        foreach {key value } $multiple_list {
			set gFilesPointer($key) $value
		}
		# bin
        #set gFilesPointer([lindex $multiple_list 0]) [lindex $multiple_list 1]
        #lib
	    #set gFilesPointer([lindex $multiple_list 2]) [lindex $multiple_list 3]
        set multiple_list 0
        # nextstr-- return: [list 32 $arr_bit(32) 64 $arr_bit(64) unknown $arr_bit(wrong) ]
        #
        puts "Processing analyze_bitnes_onLinux" 
        set multiple_list [analyze_bitnes_onLinux $gFilesPointer(bin)]
        puts "[lindex $multiple_list 0] [lindex $multiple_list 2] [lindex $multiple_list 4]"
		#return: [list 32 $arr_bit(32) 64 $arr_bit(64) unknown $arr_bit(wrong) ]
		
        set gFilesPointer(bin_32) [lindex $multiple_list 1]
    	set gFilesPointer(bin_64) [lindex $multiple_list 3]
        set gFilesPointer(bin_u)  [lindex $multiple_list 5]
    	#puts "---array keys :[array names gFilesPointer]---"
        set multiple_list 0 
    	set multiple_list [analyze_bitnes_onLinux $gFilesPointer(lib)]
    	set gFilesPointer(lib_32) [lindex $multiple_list 1]
    	set gFilesPointer(lib_64) [lindex $multiple_list 3]
    	set gFilesPointer(lib_u)  [lindex $multiple_list 5]
        
        gathering_info_lin
    }
	set new_dir_name "[pwd]/analyze[clock format [clock seconds] -format "%Y_%m_%d_%H"]"
	
    file mkdir $new_dir_name
	puts "Done 5 :  New dir $new_dir_name "
    if { $os == "windows" } {
        list_to_file_html [ html_report ] $new_dir_name     
    } else {
        list_to_file_html [ html_report_lin ] $new_dir_name
    }
   
	puts "Done at: [clock format [clock seconds] -format "%Y-%m-%d/%H:%M:%S"]"
}

#call main
main 