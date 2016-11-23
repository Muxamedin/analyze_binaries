#package require html

namespace eval  html {
    variable _body_
    variable _head_
    variable _html_
    variable _title_
    variable _include_
}

proc ::html::head {headText} {
    set ::html::_head_ $headText
}

proc ::html::title {titleText} {
    set ::html::_title_ [join [list "<title>" "$titleText" "</title>"]]
    return $::html::_title_
}

proc ::html::include {arg} {
    set ::html::_inclue_ [join [list "<script src=$arg>" "</script>"]]
    return $::html::_inclue_
}

proc ::html::head_title_src {text_head {}} {
    if { ![[string length $text_head] < 1] } {
        set ::html::_head_ $text_head 
    }
    if { ![[string length $::html::_head_] < 1] } {
        puts "Head text is empty....\n check call of \"::html::head_title_src\" in code."
        exit 
    }
    append  headTemp  $::html::_title_
    append  headTemp "\n" "$::html::_head_" "\n"
    append  headTemp "\n" "$::html::_include_" "\n"
    set ::html::_head_  $headTemp
}

proc ::html::head_append {headText} {
    append ::html::_head_ $headText
}

proc ::html::body {bodyText} {
    set ::html::_body_ $bodyText
}

proc ::html::body_append {bodyText} {
    append ::html::_body_ $bodyText
}

proc ::html::html {} {
    set  ::html::_html_ [list "<html>" \
    "<head>"  
    "$::html::_head_" \
    "</head>"  \
    "<body>" \
    "$::html::_body_" \
    "</body>" \
    "</html>" ]
}

