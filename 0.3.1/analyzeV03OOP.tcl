# Copyright (C) Electric Cloud 2016 
# Author  :  Mike Bily
# Using oop module - TcLOO
#---------------------------------------------------------------------------
package require  TclOO
# INTERFACE Igetsetter
# implantation getter and setter methods (interface) for public variables
# current class should be as superclass for another class
::oo::class create Igetsetter {
    method get arg {
        my variable $arg
        if {[info exists $arg]} {
           return [set $arg]    
        } 
    }
    method set {arg  arg1} {
        my variable $arg
        if {[info exists $arg]} {
           set $arg $arg1    
        } else {
            puts "There is no $arg field."
        }
    }
}
#---------------------------------------------------------------------------
# CLASS File - for Items which should store information about file
::oo::class create File {
	#private
	variable FileName FileSize FileSize_conv
	#public
	variable fileFolder fileOnlyName
	constructor {fName} {
        my setFileName $fName
    }
	#private:
	method FileNameOnly {} {
		set fileOnlyName [file tail $FileName ]
	}
	method FileFolder {} {
		set fileFolder [file dirname $FileName ]
	}
	method ConvertSize {} {
		set file_size $FileSize
		if { ! [ expr $file_size < 1024 ]} {
			#puts $FileSize
				if { [expr $file_size < 1048576 ]} {
					set file_size "[expr $file_size / 1024 ].[expr $file_size % 1024] Kb"
				} else {
					#set file_size_conv [expr $file_size / 1024000]
					set file_size "[expr $file_size / 1048576 ].[expr $file_size % 1048576 ] Mb"
				}		
		}
		set FileSize_conv  $file_size
		return $file_size
	}
	#end - private
	#public:
	method setFileName {fName} {
		set FileName $fName
        my fileSize
		my FileNameOnly
		my FileFolder
	}
    #re calculating FileSize and FileSize_conv
	method fileSize {} {
		set FileSize [file size $FileName]
		set FileSize_conv [my ConvertSize]
		return $FileSize_conv
    }
	method getFileSize {} {
		return  $FileSize
	}
	method getFileSize_conv {} {
		return $FileSize_conv 
	}
	method getFileName {} {
		return $FileName
	}
    method get_fileOnlyName {} {
		return $fileOnlyName
	}
    method get_fileFolder {} {
		return $fileFolder
	}
}
#---------------------------------------------------------------------------
::oo::class create FileLink {
    superclass File
    variable pointTo
    constructor {fName} {
        my setFileName $fName
    }
    method setFileName {fName} {
		my variable pointTo FileName
        set FileName $fName
        set pointTo [file readlink $fName ]
    	my FileNameOnly
		my FileFolder
	}
    method get_pointTo {} {
        return $pointTo
    }
}
#---------------------------------------------------------------------------
::oo::class create Nodes {
	variable top
	variable filesLst
	variable foldersLst
	variable libLst32
	variable libLst64
	variable exeLst32
	variable exeLst64
	constructor {Top} {
		set top $Top
		my CreateListsFilesAndFolders
    }
	#public
	## is_folder
	#     check path and return true if it is folder
	#     full_file_name : path to folder	
	#     return : true if  $full_file_name is folder
	#common
	method isFolder {full_file_name} {
		set is_folder_var 0
		if {[file isdirectory  $full_file_name]} {
			set is_folder_var 1
		} 
		return $is_folder_var
	}
	# private
	# GetFilesInFolder
	#     get list of files in folder
	#     return: list with file's names
	#common
	method GetFilesInFolder {path} {
		set curdir [pwd]	
		cd $path
		set list_of_files [glob -nocomplain -- *] 
		cd $curdir
		return $list_of_files
	}
	# private
	# create_lists_files_and_folders  - walking inside folders to get list of files
	# common
    # ToDO: change behavior  for Windows method
    # #@ ABSTRACT METHOD
	method CreateListsFilesAndFolders {} { #empty body	}
	#@ ABSTRACT METHOD
	method checkBinariesOnBitness {file_name} { #empty body }
}
#---------------------------------------------------------------------------
::oo::class create NodesLinux {
	superclass Nodes Igetsetter
    variable linkLst
	constructor {Top} {
        next $Top
   		my variable exeLst32 exeLst64 libLst32  libLst64 foldersLst filesLst linkLst
        foreach var [list exeLst32 exeLst64 libLst32  libLst64 foldersLst filesLst linkLst] {
            set $var {}
        }
    }
    
    method CreateListsFilesAndFolders {} {
		my variable top exeLst32 exeLst64 libLst32  libLst64 foldersLst filesLst linkLst
        lappend folders $top
        set linkLst {}
		set     index   0 
		while {$index < [llength $folders]} {
			set  current_item [lindex $folders $index]
			incr index
			set  list_of_files_at_folder [my GetFilesInFolder $current_item]
			foreach file_at_current_folder $list_of_files_at_folder {
				set full_path [file join $current_item $file_at_current_folder]
				if {[my isFolder $full_path]} {
					lappend folders $full_path
				} elseif {[file isfile $full_path]} {
					lappend files $full_path
					set binnaryFile [my checkBinariesOnBitness $full_path]
					lassign $binnaryFile bit type
					if { $bit > 0 } {
						if { $type == "exe" } {
							lappend exeLst$bit [File new $full_path]
						} elseif {$type == "lib"} {
							lappend libLst$bit [File new $full_path]
						} elseif {$type == "link"} {
							lappend linkLst [FileLink new $full_path]
						}
					}
				}
			}
       	}
        if {![info exists files] } {lappend files {}}
		set foldersLst $folders
		set filesLst   $files
	}
	# public:
	# checkBinariesOnBitness
	#    Read Linux binary for getting bitness
	#    file_name
	#    ELF 32-bit LSB shared object
	#linux specific
	method checkBinariesOnBitness {file_name} {
		set file [auto_execok file ]
	    catch {exec $file -e elf -b $file_name} result
	    if {[regexp {.*ELF (\d+)-bit LSB.*executable.*} $result match bit]} {
	            set binaryType exe
	    } elseif { [regexp {.*ELF (\d+)-bit LSB.*(shared object).*} $result match bit]} {
			    #TODO :  be sure that it is not a s/h link 
                set binaryType lib
		} elseif {[regexp {link} $result]} {
            set binaryType link
            set bit [file readlink $file_name ]
        } else {
			set bit 0
			set binaryType 0
		}
		return [list $bit $binaryType]
	}
}

#---------------------------------------------------------------------------
::oo::class create NodesWindows {
	superclass Nodes
	variable another
	constructor {Top} {
        next $Top
    }
	# recommended by @Eric@
	# is_32_or_64_bit_ -  Windows
	# Read Windows binary for getting bitness
	# file_name - real full file name 
	method checkBinariesOnBitness {file_name} {
		set magic ""
		set fid  [open $file_name r]
		fconfigure $fid -translation binary -encoding binary
		binary scan [read $fid 68] "a2a58i1" magic unused offset
		if {$magic != "MZ"} {
			set bit 0
			set binaryType 0
		} else {
			seek $fid $offset
			binary scan [read $fid 6] "a2a2su1" sig unused mach
			# check for PE header
			if {$sig != "PE"} {
				set bit 0
				set binaryType 0
	    	} else {
	    		if { $mach == 0x014c || $mach == 452 } {
	        		set bit "32"
	    		} elseif { $mach == 0x0200 } {
					set bit "64"
	    		} elseif { $mach == 0x8664 } {
					set bit "64"
	    		}
				set ext  [file extension $file_name]
				switch $ext {
					dll|DLL {
						set binaryType "dll" 
					}
					exe|EXE {
						set binaryType "exe" 
					}
					default {
						set binaryType "another" 
					}
				}
				
			}
		}
		if {![info exists bit]} {
			set bit 0
			set binaryType 0
		}
		close $fid
		return [list $bit $binaryType]
	}

}
#---------------------------------------------------------------------------

WFile create  fileItem "D:/1/port.tcl"
puts  [fileItem  getFilename]
puts  "fileItem  getFilename"
fileItem  setFileName "D:/2"
fileItem

puts  [fileItem  getFileSize]
Nodes create filesInFolder "D:/1"
puts "done"
filesInFolder test_data
exit
##---------------------------------------------------------------------
proc get_arguments {} {
	global argv argc
	if {$argc > 0 } {
		set file_name [lindex $argv 0]
		if { [file exists $file_name ] &&  [ file isdirectory $file_name ]} {
			set path $file_name
		} else { 
			puts "Can't access to file  $file_name - please check commandline first option" 
			exit 
		}		
	} else { 
		puts "expected \"tclsh analyzeVxx.tcl path\" - please try again" 
	}
	return $path  
}

##---------------------------------------------------------------------------