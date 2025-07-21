<?php

namespace App\Http\Middleware;

use App\Providers\RouteServiceProvider;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class RedirectIfAuthenticated
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, string ...$guards): Response
    {
        $guards = empty($guards) ? [null] : $guards;

        foreach ($guards as $guard) {
            if (Auth::guard($guard)->check()) {
                // if request is ajax
                if ($request->ajax()) {
                    return response()->json([
                        'label' => 'already_logged_in',
                        'message' => 'You are already logged in.',
                    ], 422);
                }
                return redirect('/')->with('info', [
                    'title' => 'Already Logged In',
                    'message' => 'You are already logged in.',
                ]);
            }
        }

        return $next($request);
    }
}
