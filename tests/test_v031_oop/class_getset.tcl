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