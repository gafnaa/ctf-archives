<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class RegisterWelcomeMail extends Mailable
{
    use Queueable, SerializesModels;

    /**
     * Create a new message instance.
     */
    public $data;
    public $subject = 'Welcome';
    public function __construct($data)
    {
        $this->data = (object)$data;
    }

    /**
     * Build the message.
     */
    public function build(){
        return $this->subject('Welcome')->view('mail.registerwelcome',['data' => $this->data]);
    }
}
