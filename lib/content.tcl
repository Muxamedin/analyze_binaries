namespace eval ::data {}


proc ::data::caption {} {
    set currentTime [clock format [clock seconds] -format "%dT%H:%M:%S"]
    set caption "File analyze REPORT generated from $currentTime"
    puts $caption
    return $caption
}

proc ::data::tableCreater {table_name args_lst } {
    table_name
    
    return table    
}

proc ::data::isEmptyString {str} {
    set str [string trim $str]
    expr {![binary scan $str c c]}
}
#puts [isEmptyString "  f"]

proc ::data::render {tmpl  html_out} {
    set fileid_html [open $html_out w]
    set fileid_tmpl [open $tmpl r]
    fconfigure $fileid_tmpl -encoding utf-8    
    set lineNumber 0
    while {[gets $fileid_tmpl line] >= 0} {
        if {[regexp {^(.*)<[?]tcl(.+)[?]>(.*)$} $line -> before code aftercode ] } {
            #<?tcl ::data::tableCreater stat ?>
            if {![::data::isEmptyString $before]} {
                puts $fileid_html  $before
            }
            #unset -nocomplain procedureName args txt
            set txt "eval $code"
            puts $fileid_html $txt
            if {![::data::isEmptyString $aftercode]} {
                puts $fileid_html  $aftercode
            }
        } else {
            #puts string from template
            puts $fileid_html $line
        }
    }
    close $fileid_html
    close $fileid_tmpl
}
::data::render "D:/work_tcl/analize/analyze_binaries/html/view.tmpl"   "D:/work_tcl/analize/analyze_binaries/html/index.html"
puts done
exit
#::data::title stdout
::data::caption