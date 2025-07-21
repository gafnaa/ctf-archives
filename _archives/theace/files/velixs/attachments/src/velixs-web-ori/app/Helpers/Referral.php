<?php

namespace App\Helpers;
use App\Models\User;
use App\Models\UserTransaction;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\DB;

class Referral
{
    public static function handler($ref){
        if($ref){
            if(!Cookie::has(trim(config('referral.config.cookie_name'))) || Cookie::get(trim(config('referral.config.cookie_name'))) != $ref){
                Cookie::queue(Cookie::make(
                    trim(config('referral.config.cookie_name')),
                    $ref,
                    time()+config('referral.config.expired') * 24 * 60 * 60,
                    '/'
                ));
            }
        }
    }

    public static function claim($item){
        if(Cookie::has(trim(config('referral.config.cookie_name')))){
            $user = User::where('username', Cookie::get(trim(config('referral.config.cookie_name'))))->first();
            if($user){
                if($user->id != auth()->id()){
                    try{
                        $amount = floatval($item->price['idr']) * floatval(config('referral.config.commission'));
                        DB::beginTransaction();
                        UserTransaction::create([
                            'user_id' => $user->id,
                            'type' => 'earnings',
                            'amount' => floatval($amount),
                            'description' => 'Referral Earnings from <@user:'.auth()->id().'> with an <@item:'.$item->id.'>',
                            'status' => 'approved',
                        ]);
                        $user->saldo += floatval($amount);
                        $user->save();
                        DB::commit();
                        Cookie::queue(Cookie::forget(trim(config('referral.config.cookie_name'))));
                    }catch(\Exception $e){
                        DB::rollback();
                        return false;
                    }
                } else {
                    Cookie::queue(Cookie::forget(trim(config('referral.config.cookie_name'))));
                }
            } else {
                Cookie::queue(Cookie::forget(trim(config('referral.config.cookie_name'))));
            }
        }
        return true;
    }
}
