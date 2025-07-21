<?php

namespace App\Http\Middleware;

use App\Models\Visitor;
use Closure;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class HitVisitor
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    use DispatchesJobs;
    public function handle(Request $request, Closure $next): Response
    {
        if(isset($_COOKIE['v__'])) return $next($request);
        $user_id = auth()->check() ? auth()->id() : null;
        if($user_id){
            $row = Visitor::where('user_id', $user_id);
        } else {
            $row = Visitor::where('ip', $request->ip());
        }

        if(!$row->exists()){
            $requestData = [
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'referral' => $request->fullUrl(),
                'user_id' => $user_id,
            ];
            \App\Jobs\InsertVisitorJob::dispatch($requestData);
        }
        setcookie('v__', '1', time() + 3600 * 24 * 30, '/');
        return $next($request);
    }
}
