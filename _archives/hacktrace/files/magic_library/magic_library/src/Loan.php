<?php
class Loan {
    public $items = [];
    
    public function __destruct() {
        foreach ($this->items as $item) {
            echo $item;
        }
    }
}
?>
