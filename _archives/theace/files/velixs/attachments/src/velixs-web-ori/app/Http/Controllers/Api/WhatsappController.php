<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;

class WhatsappController extends Controller
{
    public function resetPassword(Request $request){
        $request->validate([
            'data.whatsapp' => 'required',
            'secret_key' => 'required'
        ]);
        $data = (object)$request->data;
        if(RateLimiter::tooManyAttempts('whatsapp-forgot:'.$data->whatsapp, 5)) return response()->json(['message' => 'Too many attempts, Please try again later.' ], 429);

        if($request->secret_key != config('app.secret_key_api')) return response()->json(['message' => 'Secret key is incorrect.' ], 422);

        $user = User::where('whatsapp', $data->whatsapp)->first();
        if(!$user) return response()->json(['message' => 'Whatsapp not registered in any account.' ], 404);

        try {
            $token = \Str::random(60);
            DB::table('password_resets')->updateOrInsert(
                ['username' => $user->username],
                [
                    'username' => $user->username,
                    'token' => $token,
                    'created_at' => Carbon::now()
                ]
            );

            RateLimiter::hit('whatsapp-forgot:'.$data->whatsapp, 60);

            return response()->json([
                'message' => 'Reset password sent to your whatsapp.',
                'data' => [
                    'username' => $user->username,
                    'token' => $token,
                    'url' => route('password.reset', ['token' => $token, 'u' => $user->username]),
                ]
            ]);
        }catch(\Exception $e){
            return response()->json(['message' => $e->getMessage()], 500);
        }
    }
}
