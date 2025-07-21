<?php

namespace App\Http\Controllers;

use App\Helpers\Layouts;
use App\Mail\RegisterWelcomeMail;
use App\Mail\ResetPasswordMail;
use Illuminate\Support\Str;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\RateLimiter;

class AuthController extends Controller
{

    public function index(Request $request){
        if($request->method() == 'POST' && $request->ajax()){
            $request->validate([
                'username' => 'required',
                'password' => 'required',
            ]);

            if(RateLimiter::tooManyAttempts('login-attemp-lol:'.$request->ip(), 5)){
                return response()->json([
                    'message' => 'Too many login attempts. Please try again later.'
                ], 429);
            } else {
                RateLimiter::hit('login-attemp-lol:'.$request->ip());
            }

            $user = User::where('username', $request->username)->orWhere('email', $request->username)->first();
            if($user){
                if(password_verify($request->password, $user->password)){
                    Auth::login($user, (bool)$request->remember);
                    RateLimiter::clear('login-attemp-lol:'.$request->ip());
                    return response()->json([
                        'message' => 'Login success. Redirecting...',
                        'redirect' => $request->query('reff') ?? $request->session()->get('url.intended', route('main')),
                    ]);
                }else{
                    return response()->json([
                        'message' => 'Password is incorrect.'
                    ], 422);
                }
            }else{
                return response()->json([
                    'message' => 'Username or email is incorrect.'
                ], 422);
            }
        }else{
            $data['seo'] = (object)[
                'title' => 'Sign In',
            ];
            return Layouts::view('auth.login', $data);
        }
    }
    public function register(Request $request){
        if($request->method() == 'POST' && $request->ajax()) {
            $request->validate([
                'fullname' => 'required',
                'username' => 'required|max:12|regex:/^[a-z0-9]+$/|unique:users,username',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|min:8',
            ],[
                'username.regex' => 'Username can only contain letters and numbers'
            ]);

            $user = new User();
            $user->name = $request->fullname;
            $user->username = $request->username;
            $user->email = $request->email;
            $user->password = bcrypt($request->password);
            $user->save();

            Auth::login($user, true);
            return response()->json([
                'message' => 'Register success. Redirecting...',
            ]);
        } else {
            $data['seo'] = (object)[
                'title' => 'Sign Up',
            ];
            return Layouts::view('auth.register',$data);
        }
    }

    public function register_v2(Request $request){
        if($request->method() == 'POST' && $request->ajax()) {
            if(RateLimiter::tooManyAttempts('register-attemp-lol:'.$request->ip(), 1)){
                return response()->json([
                    'message' => 'Too many login attempts. Please try again later.'
                ], 429);
            }
            $request->validate([
                'fullname' => 'required|max:20',
                'username' => 'required|max:12|regex:/^[a-z0-9]+$/|unique:users,username',
                'email' => 'required|email|unique:users,email',
            ],[
                'username.regex' => 'Username can only contain letters and numbers'
            ]);

            try{
                DB::beginTransaction();
                $random = Layouts::randomPasswordDefault();

                Mail::to($request->email)->send(new RegisterWelcomeMail([
                    'name' => $request->fullname,
                    'username' => $request->username,
                    'email' => $request->email,
                    'password' => $random
                ]));

                $user = new User();
                $user->name = $request->fullname;
                $user->username = $request->username;
                $user->email = $request->email;
                $user->password = bcrypt($random);
                $user->save();

                session()->flash('register.welcome', $user);

                DB::commit();
                RateLimiter::hit('register-attemp-lol:'.$request->ip());
                return response()->json([
                    'message' => 'Register success. Redirecting...',
                ]);
            }catch(\Exception $e){
                DB::rollBack();
                return response()->json([
                    'message' => $e->getMessage()
                ], 422);
            }
        } else {
            $data['seo'] = (object)[
                'title' => 'Sign Up',
            ];
            return Layouts::view('auth.register_v2',$data);
        }
    }

    public function register_welcome(){
        if(!session()->has('register.welcome')) return redirect()->route('login');
        return Layouts::view('auth.register_welcome',[
            'user' => session()->get('register.welcome')
        ]);
    }

    public function forgot(Request $request) {
        if($request->method() == 'POST') {
            $request->validate([
                'email' => 'required|email',
            ]);

            $user = User::where('email', $request->email)->first();
            if(!$user) return back()->with('error', ['title' => 'Email Not Found', 'message' => 'Email not registered in any account.']);

            try{
                $token = Str::random(60);
                DB::table('password_resets')->updateOrInsert(
                    ['username' => $user->username],
                    [
                        'username' => $user->username,
                        'token' => $token,
                        'created_at' => Carbon::now()
                    ]
                );
                Mail::to($user->email)->send(new ResetPasswordMail([
                    'name' => $user->name,
                    'username' => $user->username,
                    'token' => $token,
                    'url' => route('password.reset', ['token' => $token, 'u' => $user->username]),
                ]));

                return back()->with('success', ['title' => 'Email Sent', 'message' => 'Please check your email inbox and follow the instructions inside to reset your password']);
            } catch(\Exception $e){
                return back()->with('error', ['title' => 'Email Not Sent', 'message' => $e->getMessage()]);
            }
        } else {
            $data['seo'] = (object)[
                'title' => 'Forgot Password',
            ];
            return Layouts::view('auth.forgot',$data);
        }
    }

    public function reset($token){
        $username = request()->get('u');
        if(!$username || !$token) return redirect()->route('login')->with('info', ['title' => 'Reset Password', 'message' => 'Please check your email inbox and follow the instructions inside to reset your password']);
        return Layouts::view('auth.reset', ['token' => $token, 'username' => $username]);
    }

    public function resetpost(Request $request){
        if($request->method() == 'POST' && $request->ajax()){
            $request->validate([
                'token' => 'required',
                'username' => 'required',
                'password' => 'required|min:8',
                'password_confirmation' => 'required|same:password',
            ]);

            $user = User::where('username', $request->username)->first();
            if(!$user) return response()->json(['message' => "We could not find the username."], 422);

            $tokenData = DB::table('password_resets')->where([
                ['username', $request->username],
                ['token', $request->token]
            ])->first();

            if(!$tokenData) return response()->json(['message' => "Token is invalid."], 422);

            $user->forceFill([
                'password' => bcrypt($request->password),
            ])->setRememberToken(null);
            $user->save();
            event(new PasswordReset($user));
            DB::table('password_resets')->where([
                ['username', $request->username],
                ['token', $request->token]
            ])->delete();

            return response()->json([
                'message' => 'Password reset success. Redirecting...',
                'redirect' => route('login'),
            ]);
        }
    }

    public function logout(){
        Auth::logout();
        return redirect()->route('login')->with('success', [
            'title' => 'Logout Success',
            'message' => 'You have been logged out.',
        ]);
    }
}
