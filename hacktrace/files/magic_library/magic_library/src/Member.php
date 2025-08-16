<?php
class Member {
    public $name;
    public $borrowed = [];
    
    public function checkout() {
        return system("echo 'Checked out: " . implode(", ", $this->borrowed) . "'");
    }
}
?>
