<?php

namespace App\Jobs;

use App\Models\Visitor;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Stevebauman\Location\Facades\Location;
use Jenssegers\Agent\Agent;

class InsertVisitorJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;
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
        $ip = $this->request->ip;
        $row = null;
        if($this->request->user_id){
            $row = Visitor::where('user_id', $this->request->user_id);
        } else {
            $row = Visitor::where('ip', $ip);
        }

        if(!$row->exists()){
            $location = Location::get($ip);
            $agent = new Agent();
            $agent->setUserAgent($this->request->user_agent);
            Visitor::create([
                'ip' => $ip,
                'user_id' => $this->request->user_id,
                'user_agent' => $this->request->user_agent,
                'browser' => $agent->browser(),
                'country' => $location->countryName ?? 'Unknown',
                'referral' => $this->request->referral,
            ]);
        }
    }
}
