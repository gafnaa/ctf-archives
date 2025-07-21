<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class License extends Model
{
    use HasFactory;

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

    protected $guarded = [];

    protected $dates = [
        'created_at',
        'updated_at',
        'expires_at'
    ];


    public function _item()
    {
        if($this->item=='digital-product') {
            return $this->belongsTo(Product::class, 'item_id');
        } else {
            return null;
        }
    }
}
