<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Visitor extends Model
{
    use HasFactory;

    protected $guarded = [];

    protected $keyType = 'string';
    public $incrementing = false;
    protected $primaryKey = 'id';

    // boot uuid
    protected static function boot()
    {
        parent::boot();
        static::creating(function ($model) {
            $model->{$model->getKeyName()} = (string) \Str::uuid();
        });
    }

    public function _user()
    {
        if($this->user_id){
            return $this->belongsTo(User::class, 'user_id', 'id');
        } else {
            return null;
        }
    }

    public static function countBrowser(){
        return self::selectRaw('CASE WHEN browser IN ("Chrome", "Mozilla", "Edge", "Safari", "Opera") THEN browser ELSE "Unknown" END AS browser_group, COUNT(*) as total_views , ROUND(COUNT(*) * 100 / (SELECT COUNT(*) FROM visitors), 2) AS percentage')
            ->groupBy('browser_group')
            ->orderBy('total_views','DESC')
            ->get();
    }

    public static function countCountry(){
        return self::selectRaw('country, count(*) as total, ROUND(COUNT(*) * 100 / (SELECT COUNT(*) FROM visitors), 2) AS percentage')
            ->groupBy('country')
            ->orderBy('total','DESC')
            ->limit(7)
            ->get();
    }

    public static function countPageView(){
        return self::selectRaw('referral, count(*) as total, ROUND(COUNT(*) * 100 / (SELECT COUNT(*) FROM visitors), 2) AS percentage')
            ->groupBy('referral')
            ->orderBy('total','DESC')
            ->limit(7)
            ->get();
    }
}
