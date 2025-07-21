<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class IsAdmin
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if($request->ajax()){
            if(auth()->check()){
                if(auth()->user()->role == 'admin'){
                    return $next($request);
                }else{
                    return response()->json([
                        'message' => 'You are not authorized to access this page'
                    ],403);
                }
            }else{
                return response()->json([
                    'message' => 'You are not authorized to access this page'
                ],403);
            }
        } else {
            if(auth()->check()){
                if(auth()->user()->role == 'admin'){
                    return $next($request);
                }else{
                    return redirect()->route('main')->with('bug','You are not authorized to access this page');
                }
            }else{
                return redirect()->route('main')->with('bug','You are not authorized to access this page');
            }
        }
    }
}
