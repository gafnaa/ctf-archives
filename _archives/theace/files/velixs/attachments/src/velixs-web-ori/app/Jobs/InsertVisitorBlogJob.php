<?php

namespace App\Jobs;

use App\Models\BlogView;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Stevebauman\Location\Facades\Location;

class InsertVisitorBlogJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * Create a new job instance.
     */

    protected $request;

    public function __construct($request)
    {
        $this->request = (object)$request;
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        $user_id = $this->request->user_id;
        $ip = $this->request->ip_address;
        $row = null;
        if($user_id){
            $row = BlogView::where('blog_id',$this->request->blog_id)->where('user_id', $user_id);
        } else {
            $row = BlogView::where('blog_id',$this->request->blog_id)->where('ip_address', $ip);
        }

        if(!$row->exists()){
            BlogView::create([
                'blog_id' => $this->request->blog_id,
                'user_id' => $user_id,
                'ip_address' => $ip,
                'country' => Location::get($ip)->countryName ?? 'Unknown'
            ]);
        }
    }
}
