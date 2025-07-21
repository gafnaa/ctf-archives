<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Storage;

class Apihub extends Model
{
    use HasFactory;

    protected $guarded = [];

    protected $dates = [
        'created_at',
        'updated_at',
    ];

    protected $casts = [
        'tags' => 'array',
    ];

    public function _image(){
        return Storage::exists($this->image ?? '') ? asset('storage/'.$this->image) : asset('storage/apis/default.png');
    }

    public function _thumbnail(){
        // return $this->thumbnail ? asset('storage/'.$this->thumbnail) : $this->_image();
        return $this->thumbnail ? asset('storage/'.$this->thumbnail) : null;
    }

    public function _author(){
        return $this->belongsTo(User::class,'author');
    }

    public function _tags($col = null) {
        try {
            $tags_id = $this->tags;
            $tags = [];
            foreach ($tags_id as $tag_id) {
                $tag = ApihubTags::find($tag_id);
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
}

