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
   		#my variable exeLst32 exeLst64 libLst32  libLst64 foldersLst filesLst linkLst
        #foreach var [list exeLst32 exeLst64 libLst32  libLst64 foldersLst filesLst linkLst] {
        #    set $var {}
        #}
    }
    
    method CreateListsFilesAndFolders {} {
		my variable top exeLst32 exeLst64 libLst32  libLst64 foldersLst filesLst linkLst
        lappend folders $top
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

puts "Start"
#NodesLinux create ContainerOfFiles "/tmp/test"
#
NodesLinux create ContainerOfFiles "/opt/ecloud"
puts "[ContainerOfFiles get top]"
puts "\#---files"
puts "Files : [llength [ContainerOfFiles get filesLst]]"
puts "\#---folders"
puts "Folders: [llength [ContainerOfFiles get foldersLst]]"
puts "\#---"
puts "\#---lib32"
puts "[llength [ContainerOfFiles get libLst32]]"
puts "\#---"
puts "\#---lib64"
set libLst64 [ContainerOfFiles get libLst64]
puts "[llength $libLst64]"
puts "\#---"
puts "\#---exe64"
puts "[llength [ContainerOfFiles get exeLst64]]"
puts "\#---"
puts "\#---exe32"
set exeLst32 [ContainerOfFiles get exeLst32]
puts "[llength $exeLst32]"
puts "\#---"
puts "\#--- lib64"
foreach i $libLst64 {
    puts "[incr cnt]: [$i get_fileFolder] | [$i get_fileOnlyName] | [$i getFileSize]"
}
puts "\#---"
puts "\#---links"
set linkLst [ContainerOfFiles get linkLst]
puts "lenght \n [llength $linkLst]"
foreach ii $linkLst {
    puts "[incr cntl]: [$ii get_fileFolder] | [$ii get_fileOnlyName] | [$ii get_pointTo]"
}
puts "\#---"
puts "End"