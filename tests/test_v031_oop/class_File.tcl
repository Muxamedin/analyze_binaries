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