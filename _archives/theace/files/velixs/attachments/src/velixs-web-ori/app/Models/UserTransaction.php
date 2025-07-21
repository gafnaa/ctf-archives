<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class UserTransaction extends Model
{
    use HasFactory;

    protected $guarded = [];

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

    protected $dates = [
        'created_at',
        'updated_at',
    ];

    public function _user(){
        return $this->belongsTo(User::class, 'user_id');
    }

}
