<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ApihubEndpoint extends Model
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

    protected $dates = ['created_at','updated_at'];
}
