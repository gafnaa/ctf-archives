<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class Suspended
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if(auth()->check()){
            if(auth()->user()->suspended){
                if($request->ajax()){
                    return response()->json([
                        'message' => 'Your account has been suspended'
                    ],403);
                } else {
                    return redirect()->route('sus')->with('bug','Your account has been suspended');
                }
            }
        }
        return $next($request);
    }
}
