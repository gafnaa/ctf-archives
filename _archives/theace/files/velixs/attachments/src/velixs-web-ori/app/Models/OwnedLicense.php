<?php

namespace App\Models;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class OwnedLicense extends Model
{
    use HasFactory;

    protected $guarded = [];
    protected $dates = ['expires_at', 'created_at', 'updated_at'];

    //  uuid
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

    public function _item()
    {
        if($this->item=='digital-product') {
            return $this->belongsTo(Product::class, 'item_id');
        } else {
            return null;
        }
    }

    public function _user(){
        return $this->belongsTo(User::class, 'user_id');
    }

    public function _expires_at()
    {
        if($this->expires_at) {
            $now = Carbon::now();
            $expires_at = Carbon::parse($this->expires_at);
            return $expires_at->diffInDays($now);
        } else {
            return '-';
        }
    }
}
