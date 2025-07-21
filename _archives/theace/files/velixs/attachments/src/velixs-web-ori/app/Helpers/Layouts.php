<?php

namespace App\Helpers;

use App\Models\Blog;
use App\Models\OwnedLicense;
use App\Models\Websettings;

class Layouts
{
    public static function view($view, $data = [], $mergeData = []){
        $data['ws'] = Websettings::getWebsiteSettings();
        $data['auth'] = auth()->user();
        $data['recent_posts'] = Blog::RecentPosts();
        return view($view, $data, $mergeData);
    }

    public static function meta_title($title){
        return $title.' | Velixs';
    }


    public static function MakeLicense($for = 'digital-product'){
        if($for=='digital-product'){
            // like VELIXS-DIPG-0001-SD22-SW34-WDAA
            do{
                $license = 'VELIXS-DIPG-'.rand(1000,9999).'-'.strtoupper(substr(md5(rand(1000,9999)), 0, 4)).'-'.strtoupper(substr(md5(rand(1000,9999)), 0, 4)).'-'.strtoupper(substr(md5(rand(1000,9999)), 0, 4));
                $check = OwnedLicense::where([
                    'item' => 'digital-product',
                    'license_key' => $license,
                ]);
            }while($check->exists());
            return $license;
        }else{
            return false;
        }
    }

    public static function generateUniqueSlug($length = 10) {
        $characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
        $slug = '';

        for ($i = 0; $i < $length; $i++) {
            $randomIndex = rand(0, strlen($characters) - 1);
            $slug .= $characters[$randomIndex];
        }

        return $slug;
    }

    public static function randomPasswordDefault($length = 10) {
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $password = '';

        for ($i = 0; $i < $length; $i++) {
            $password .= $characters[rand(0, strlen($characters) - 1)];
        }

        return $password;
    }

    // short number
    public static function shortNumber($number){
        if($number >= 1000000000){
            $number = round($number/1000000000, 1).'B';
        }else if($number >= 1000000){
            $number = round($number/1000000, 1).'M';
        }else if($number >= 1000){
            $number = round($number/1000, 1).'K';
        }
        return $number;
    }
}
