#tcl script for windows 
#task:
#1) get argument - what folder to analise
#3) create folder structure 
#3) analize binary(exe,dll) files at folder.
#4) result -  files (wiki mark up  or Html)  with repotr
#report structure : 
#     tree in folder 
#     table with summary 32-bit / 64-bit exe/dll files 
#---------------------------------------------------------
#


#array set gFilesPointer [list topFolder $gFolder_top]
#array set gFilesPointer 

proc get_arguments { } {
#
	global argv argc
	#global $var_folder_top
	if { $argc > 0  } {
		set file_name [lindex $argv 0]
		if { [file exists $file_name ] &&  [ file isdirectory $file_name ]} {
			set path $file_name
			} else { 
				puts "can't acces to file  $file_name - please check argument" 
				vwait 2000
				exit 
			}		
		} else { 
			puts "expected \"tclsh analize.tcl path\" - please try again" 
			vwait 2000
		}
	return $path  
}

proc get_files_in_folder { path } {
## return file name  list
	set curdir [pwd]	
	cd $path
	set files_list [glob -nocomplain -- *] 
	cd $curdir
	return $files_list
}

proc is_folder { full_file_name } {
#??
	set is_folder_var 0
	if { [file isdirectory  $full_file_name] } {
		set is_folder_var 1
	} 
	return $is_folder_var
}

proc  create_lists_files_and_folders { path } {
	global gFilesPointer gFolders 
	set    root_folder $path
	lappend folders  $root_folder
	set    index 0 
	# analize list 
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


proc is_exe { file_name } {
#
	set is_exe_ 0
	set ext [file extension $file_name]
	if { [ string match ".exe" $ext]} {
		set is_exe_ 1
	}
	return $is_exe_
}
proc is_dll { file_name } {
	set is_dll_ 0
	set ext [file extension $file_name]
	if {[string match ".dll"  $ext ]} {
		set is_dll_ 1
	}
	return $is_dll_
}

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

# recommended by @Eric@
proc is_32_or_64_bit_ { file_name } {
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


proc analize_bitnes_forWindows { files_list} {
	array set arr_bit [list 32 {} 64 {} wrong {}]
	foreach i_file $files_list {
		set prefix [is_32_or_64_bit_ $i_file]
		lappend  arr_bit($prefix)  $i_file
		
	}
	#
	return [list 32 $arr_bit(32) 64 $arr_bit(64) unknown $arr_bit(wrong) ] 
}

proc p_file_size { file_path } {
	set file_size [file size $file_path]
	return [ size_convertor $file_size ]	
}

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
	set cnt 0
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
proc list_to_file_html { list_data folder } {
	set time [clock format [clock seconds] -format "%Y-%m-%d-%H-%M-%S"]
	append file_name  $folder "/html_report_" $time ".html"
	
	set fid [open   $file_name  w]
	foreach i  $list_data  {
		puts $fid $i
	}
	close $fid

}
proc gathering_info {} {
	set tcl_precision 3
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
	set gFilesPointer(dll,size) [expr $gFilesPointer(size_32_dll) + $gFilesPointer(size_64_dll)]
	set gFilesPointer(dll,count) [ expr [llength $gFilesPointer(dll_32)] + [llength $gFilesPointer(dll_64)]] 
	set gFilesPointer(dll,percent_of_total) [expr ($gFilesPointer(dll,size)*100.) / $gFilesPointer(all_files_size)]  


	set gFilesPointer(exe,size) [expr $gFilesPointer(size_32_exe) + $gFilesPointer(size_64_exe)]
	set gFilesPointer(exe,count) [ expr [llength $gFilesPointer(exe_32)] + [llength $gFilesPointer(exe_64)]] 
	set gFilesPointer(exe,percent_of_total) [expr ($gFilesPointer(exe,size)*100.000) / $gFilesPointer(all_files_size)]  

	
	set gFilesPointer(dll_32,count) [llength $gFilesPointer(dll_32)]
	set gFilesPointer(dll_32,percent_of_total) [expr ($gFilesPointer(size_32_dll)*100.000) / $gFilesPointer(all_files_size)] 

	
	set gFilesPointer(dll_64,count) [llength $gFilesPointer(dll_64)]
	set gFilesPointer(dll_64,percent_of_total) [expr ($gFilesPointer(size_64_dll)*100.000) / $gFilesPointer(all_files_size)]  

	set gFilesPointer(exe_32,count) [llength $gFilesPointer(exe_32)]
	set gFilesPointer(exe_32,percent_of_total) [expr ($gFilesPointer(size_32_exe)*100.000) / $gFilesPointer(all_files_size)] 

	set gFilesPointer(exe_64,count) [llength $gFilesPointer(exe_64)]
	set gFilesPointer(exe_64,percent_of_total) [expr ($gFilesPointer(size_64_exe)*100.000) / $gFilesPointer(all_files_size)] 

	
	set gFilesPointer(exe_u,count) [llength $gFilesPointer(exe_u)]
	set gFilesPointer(exe_u,percent_of_total) [expr ($gFilesPointer(size_u_exe)*100.000) / $gFilesPointer(all_files_size)]  

	set gFilesPointer(dll_u,count) [llength $gFilesPointer(dll_u)]
	set gFilesPointer(dll_u,percent_of_total) [expr ($gFilesPointer(size_u_dll)*100.000) / $gFilesPointer(all_files_size)]

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


proc main {} {
	global gFilesPointer gFolder_top
	set gFolder_top [get_arguments]
	set gFilesPointer(topFolder) $gFolder_top
	puts " Start at: [clock format [clock seconds] -format "%Y-%m-%d/%H:%M:%S"]"
	set multiple_list 0 
	set multiple_list [create_lists_files_and_folders $gFolder_top]
	set gFilesPointer([lindex $multiple_list 0]) [lindex $multiple_list 1]
	set gFilesPointer([lindex $multiple_list 2]) [lindex $multiple_list 3]
	#puts "array keys :[array names gFilesPointer]"

	set multiple_list 0 
	set multiple_list [separate_dll_exe $gFilesPointer(files)]
	set gFilesPointer([lindex $multiple_list 0]) [lindex $multiple_list 1]
	set gFilesPointer([lindex $multiple_list 2]) [lindex $multiple_list 3]
	#puts "---array keys :[array names gFilesPointer]---"
	set multiple_list 0 
	set multiple_list [analize_bitnes_forWindows $gFilesPointer(exe)]
	#puts "-----"
	puts "[lindex $multiple_list 0] [lindex $multiple_list 2] [lindex $multiple_list 4]"
	set gFilesPointer(exe_32) [lindex $multiple_list 1]
	set gFilesPointer(exe_64) [lindex $multiple_list 3]
	set gFilesPointer(exe_u) [lindex $multiple_list 5]
	#puts "---array keys :[array names gFilesPointer]---"
	set multiple_list 0 
	set multiple_list [analize_bitnes_forWindows $gFilesPointer(dll)]
	#puts "[lindex $multiple_list 0] [lindex $multiple_list 2] [lindex $multiple_list 4]"
	set gFilesPointer(dll_32) [lindex $multiple_list 1]
	set gFilesPointer(dll_64) [lindex $multiple_list 3]
	set gFilesPointer(dll_u)  [lindex $multiple_list 5]

	
	gathering_info
	set new_dir_name "[pwd]/analize[clock format [clock seconds] -format "%Y_%m_%d_%H"]"
	file mkdir $new_dir_name
	list_to_file_wmr  [ wiki_markap_report ] $new_dir_name
	list_to_file_html [ html_report ] $new_dir_name
	list_to_file_wmr  [atlassian_wiki_markap_report] $new_dir_name
	
	puts [clock format [clock seconds] -format "%Y-%m-%d/%H:%M:%S"]
}

main 