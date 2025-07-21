<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Facades\Cache;
use Stevebauman\Location\Facades\Location;

class Blog extends Model
{
    use HasFactory, SoftDeletes;

    protected $guarded = [];

    protected $dates = ['deleted_at', 'created_at', 'updated_at'];

    protected $casts = [
        'tags' => 'array',
    ];

    public static function RecentPosts(){
        return Cache::remember('recent_posts', 60 * 24, function () {
            return self::select('id', 'title', 'slug', 'created_at')
                ->orderBy('created_at', 'desc')
                ->limit(3)
                ->get();
        });
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
                $tag = BlogTags::find($tag_id);
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

    public function traffic() {
        return $this->hasMany(BlogView::class, 'blog_id');
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
