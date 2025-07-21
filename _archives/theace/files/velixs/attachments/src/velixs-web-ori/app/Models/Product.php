<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Product extends Model
{
    use HasFactory,SoftDeletes;

    protected $guarded = [];

    protected $dates = ['deleted_at', 'created_at', 'updated_at'];

    protected $casts = [
        'tags' => 'array',
        'price' => 'array',
        'release' => 'array',
    ];

    public function _route(){
        return route('product.detail', $this->slug);
    }

    public function _author()
    {
        return $this->belongsTo(User::class, 'author');
    }

    public function _image()
    {
        return $this->image ? asset('storage/'.$this->image) : asset('storage/blogs/default.png');
    }

    public function _tags($col = null) {
        try {
            $tags_id = $this->tags;
            $tags = [];
            foreach ($tags_id as $tag_id) {
                $tag = ProductTags::find($tag_id);
                if ($tag) {
                    array_push($tags, $tag);
                }
            }
            if($col){
                $tags = collect($tags)->pluck($col);
            }
            return $tags;
        }catch (\Exception $e){
            return [];
        }
    }

    public function _hasWishlist($auth = null){
        if(!$auth) return null;
        return in_array($this->id, $auth->digital_product_wishlist);
    }

    public function _hasOwned($auth = null){
        if(!$auth) return null;
        return OwnedLicense::where([
            'user_id' => $auth->id,
            'item_id' => $this->id,
            'item' => 'digital-product'
        ])->exists();
    }

    public function _latestRelease(){
        $release = $this->release;
        if(!$release) return null;
        return isset($release['latest']) ? $release['latest'] : $release = null;
    }

    public function _archiveRelease(){
        $release = $this->release;
        if(!$release) return [];
        return isset($release['archive']) ? $release['archive'] : $release = [];
    }

    public function _display_price($currency = 'usd'){
        $price = $this->price;
        if($this->github) return '<div class="flex items-center"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" style="margin-right: 1px" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M9 19c-4.3 1.4 -4.3 -2.5 -6 -3m12 5v-3.5c0 -1 .1 -1.4 -.5 -2c2.8 -.3 5.5 -1.4 5.5 -6a4.6 4.6 0 0 0 -1.3 -3.2a4.2 4.2 0 0 0 -.1 -3.2s-1.1 -.3 -3.5 1.3a12.3 12.3 0 0 0 -6.2 0c-2.4 -1.6 -3.5 -1.3 -3.5 -1.3a4.2 4.2 0 0 0 -.1 3.2a4.6 4.6 0 0 0 -1.3 3.2c0 4.6 2.7 5.7 5.5 6c-.6 .6 -.6 1.2 -.5 2v3.5"></path></svg> <span>GitHub</span></div>';
        if($this->_isFree()) return 'FREE';
        if($currency == 'idr') {
            if(isset($price['idr'])){
                return 'Rp. '.number_format($price['idr'], 0, ',', '.');
            }
        }else if($currency == 'usd'){
            if(isset($price['usd'])){
                return '$'.number_format($price['usd'], 2, ',', '.');
            }
        }
        return 0;
    }

    public function _price($currency = 'usd'){
        $price = $this->price;
        if($currency == 'idr') {
            if(isset($price['idr'])){
                return $price['idr'];
            }
        }else if($currency == 'usd'){
            if(isset($price['usd'])){
                return $price['usd'];
            }
        }
        return 0;
    }

    public function _isFree(){
        return (bool) $this->is_free;
    }

    public function traffic() {
        return $this->hasMany(ProductVisitor::class, 'product_id');
    }

    public static function paidOnly(){
        return self::where("is_published", '!=', 0)->where("is_free", 0);
    }

    public function countView(){
        // format: 1,000
        return number_format($this->traffic()->count());
    }

    public function _countViewShort(){
        $satuan = ['', 'K', 'M', 'B', 'T'];
        $angka = $this->traffic()->count();
        $satuan_index = 0;
        while ($angka >= 1000) {
            $angka /= 1000;
            $satuan_index++;
        }
        return round($angka, 2) . ' ' . $satuan[$satuan_index];
    }
}
