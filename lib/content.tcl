namespace eval ::data {}
proc ::data::caption {} {
    set currentTime [clock format [clock seconds] -format "%dT%H:%M:%S"]
    set caption "File analyze REPORT generated from $currentTime"
    puts $caption
    return $caption
}

proc ::data::isEmptyString {str} {
    set str [string trim $str]
    expr {![binary scan $str c c]}
}

proc ::data::tableCreater {lstName cntInTable} {
    upvar #0 $lstName refTolstName
    set cnt 0
    set txtBodyTable {}
    #append txtBodyTable
    set lstLentgth [llength $refTolstName]
    foreach item $refTolstName {
        #incr cnt
        if { ($cnt % $cntInTable) == 0 } {
            # devide list on cntInTable  items
            switch -- $cnt {
                0 {
                    append txtBodyTable "\n <tr> \n <td>$item</td>\n"
                }
                $lstLentgth {
                    append txtBodyTable "</tr>\n"
                }
                default {
                    append txtBodyTable "</tr> \n <tr> \n <td>$item</td>\n"
                }
            }
        } else {
            append txtBodyTable "<td>$item</td>\n"    
        }
        
    }
    return $txtBodyTable
}

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
                set cntchars [string legth $before]
            }
            set txt [eval $code] 
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