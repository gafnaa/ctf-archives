<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;

class Websettings extends Model
{
    use HasFactory;

    protected $guarded = [];

    public static function getWebsiteSettings(){
        return Cache::remember('website_settings', 60 * 24, function () {
            return self::first();
        });
    }

    public static function _logo(){
        $ws = self::getWebsiteSettings();
        return $ws->logo;
    }

    public function _social_links(){
        return json_decode($this->social_links ?? '[]');
    }

    public function _contact_whatsapp(){
        return json_decode($this->contact_whatsapp ?? '[]');
    }

    public function _payment_whatsapp($url){
        return 'https://wa.me/'.$this->payment_whatsapp.'?text=Hi, I want to buy your product.\n*'.$url.'*';
    }

    public function _fogot_whatsapp(){
        return 'https://wa.me/'.$this->bot_whatsapp.'?text=/forgot';
    }
}
