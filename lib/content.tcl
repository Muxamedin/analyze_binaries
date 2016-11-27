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
#for testing of rendering html 
set libraries    [list Bububu 32b 64 D:/1  bu0 32b 64 D:/1 Coza 32b 64 D:/1 ]
set dependencies [list lib 45Mb 32  yes no "blablabla" lib1 45Mb 32  yes no "blablabla"]
set binaries     [list application 45Mb 32 "/tmp" "lob snob bob"]
set stat         [list lib 12Mb 32  12 bin 12Mb 23  15 ]
set all          [list tclsh "/tmp/oppp/colobolbob" yes no 12Mb]
set summary      [list cat  no yes "../../Ecloud" linux  no no tac  no yes "../../Ecloud" linux  no no ls  no yes "../../Ecloud" linux  no no ]
#should be cleared for next development

proc ::data::tableCreater {lstName cntInTable} {
    upvar #0 $lstName refTolstName
    set cnt 0
    set txtBodyTable {}
    set lstLentgth [llength $refTolstName]
    foreach item $refTolstName {
        if { ($cnt % $cntInTable) == 0 } {
            incr cnt_rows
            # devide list on cntInTable items
            switch -- $cnt {
                0 {
                    append txtBodyTable "<tr> \n <td class=red>$cnt_rows</td> \n <td class=green>$item</td>\n"
                    
                }
                $lstLentgth {
                    append txtBodyTable "</tr>\n"
                }
                default {
                    append txtBodyTable "</tr> \n <tr> \n <td class=red>$cnt_rows</td> \n <td class=green>$item</td>\n"
                    
                }
            }
            
        } else {
            append txtBodyTable "<td class=green >$item</td>\n"    
        }
        incr cnt
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
            if {![::data::isEmptyString $before]} {
                puts $fileid_html  $before
                set cntchars [string length $before]
            }
            set txt [eval $code] 
            puts $fileid_html $txt
            if {![::data::isEmptyString $aftercode]} {
                puts $fileid_html  $aftercode
            }
        } else {
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