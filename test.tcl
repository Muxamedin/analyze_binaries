
# class interface
# Igetter - getter method for public fields in object
::oo::class create Igetter {
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
# test for File class
# 
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
		#my FileNameOnly
		#my FileFolder
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
        my FileNameOnly
		return $fileOnlyName
	}
    method get_fileFolder {} {
        my FileFolder
		return $fileFolder
	}
}
#File create Item "F:/vspinstllers/VSIntegration-5.1.0.36170-Install.exe"
#
#
puts "Creating obj File for /bin/bash "
File create Item "/bin/bash"
puts "-------------Item"
puts "Get file Name from obj:"
puts [Item getFileName]
puts "-----------------"
puts "!Get file size from obj"
puts [Item getFileSize]
puts "-----------------"
puts "Get size of file"
puts [Item fileSize]
puts "-----------------"
puts "Get conv file size"
puts [Item getFileSize_conv]
puts "-----------------"
puts "Get FileName Only"
puts [Item get_fileOnlyName]
puts "-----------------"
puts "-------------------------------------------"
#Item setFileName "F:/vspinstllers/VSIntegration-5.1.0.36193-Install.exe"

Item setFileName "/bin/cat"
puts "-------------renamed file"
puts "Get file Name from obj:"
puts [Item getFileName]
puts "-----------------"
puts "Get file size from obj"
puts [Item getFileSize]
puts "-----------------"
puts "Get size of file"
puts [Item fileSize]
puts "-----------------"
puts "Get conv file size"
puts [Item getFileSize_conv]
puts "-----------------"
puts "Get FileName Only"
puts [Item get_fileOnlyName]
puts "-----------------"

puts "getFilename- [Item getFileName]"
puts "getFileSize- [Item getFileSize]"
puts "fileSize-    [Item fileSize]"
puts "getFileSize- [Item getFileSize]"
puts "getFileSize_conv- [Item getFileSize_conv]"
puts "get_fileOnlyName- [Item get_fileOnlyName]"
puts "-------------------------------------------"
puts "another way "
puts [set [info object namespace Item]::fileOnlyName]
puts [Item getFileName]
puts [Item getFileSize_conv]
puts [Item get_fileOnlyName]
puts "-------------------------------------------"

Item setFileName "/bin/ls"
puts "-------------renamed file"
puts "Get file Name from obj:"
puts [Item getFileName]
puts "-----------------"
puts "Get file size from obj"
puts [Item getFileSize]
puts "-----------------"
puts "Get size of file"
puts [Item fileSize]
puts "-----------------"
puts "Get conv file size"
puts [Item getFileSize_conv]
puts "-----------------"
puts "Get FileName Only"
puts [Item get_fileOnlyName]
puts "-----------------"

puts "getFilename- [Item getFileName]"
puts "getFileSize- [Item getFileSize]"
puts "fileSize-    [Item fileSize]"
puts "getFileSize- [Item getFileSize]"
puts "getFileSize_conv- [Item getFileSize_conv]"
puts "get_fileOnlyName- [Item get_fileOnlyName]"
puts "get_fileFolder- [Item get_fileFolder]"
puts "-------------------------------------------"
puts "another way "
puts [set [info object namespace Item]::fileOnlyName]
puts [Item getFileName]
puts [Item getFileSize_conv]
puts [Item get_fileOnlyName]
puts "-------------------------------------------"
