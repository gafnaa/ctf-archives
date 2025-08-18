<?php
class Book {
    public $title;
    public $author;
    
    public function __wakeup() {
        echo "Processing book: " . htmlspecialchars($this->title);
    }
}
?>
