<?php
class Library {
    public $name;
    public $collection;
    
    public function __toString() {
        return $this->collection->checkout();
    }
}
?>
