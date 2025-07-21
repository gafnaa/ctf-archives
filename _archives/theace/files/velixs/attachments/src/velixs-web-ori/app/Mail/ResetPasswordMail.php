<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class ResetPasswordMail extends Mailable
{
    use Queueable, SerializesModels;

    /**
     * Create a new message instance.
     */
    public $data;
    public $subject = 'Reset Password';
    public function __construct($data)
    {
        $this->data = (object)$data;
    }

    /**
     * Build the message.
     */
    public function build(){
        return $this->subject('Reset Password')->view('mail.resetpassword',['data' => $this->data]);
    }
}
