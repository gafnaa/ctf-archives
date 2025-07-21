<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;

use Illuminate\Auth\Passwords\CanResetPassword;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable, CanResetPassword;

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

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'avatar',
        'username',
        'email',
        'whatsapp',
        'role',
        'password',
        'digital_product_wishlist',
        'saldo',
        'api_key',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
        'digital_product_wishlist' => 'array',
    ];

    public function _avatar(){
        return $this->avatar ? asset('storage/'.$this->avatar) : asset('storage/avatars/default.png');
    }

    public function _verified(){
        if($this->role == 'admin'){
            return true;
        }
        return false;
    }

    public function _owned_license(){
        return $this->hasMany(OwnedLicense::class, 'user_id');
    }

    public function _count_license(){
        $angka = $this->_owned_license()->count();
        $satuan = ['', 'K', 'M', 'B', 'T'];
        $satuan_index = 0;
        while ($angka >= 1000) {
            $angka /= 1000;
            $satuan_index++;
        }
        return round($angka, 2) . ' ' . $satuan[$satuan_index];
    }

    public function _count_wishlist(){
        $angka = count($this->digital_product_wishlist);
        $satuan = ['', 'K', 'M', 'B', 'T'];
        $satuan_index = 0;
        while ($angka >= 1000) {
            $angka /= 1000;
            $satuan_index++;
        }
        return round($angka, 2) . ' ' . $satuan[$satuan_index];
    }
}
