<?php

namespace App\Http\Livewire;

use App\Models\Apihub;
use App\Models\ApihubTags;
use Livewire\Component;
use Livewire\WithPagination;

class Rapi extends Component
{
    use WithPagination;

    protected $model = Apihub::class;
    protected $perPage = 20;
    public $tag = null;
    public $sort = null;
    public $collection = null;
    protected $queryString = [
        'tag' => ['except' => null],
    ];

    public function mount($tag, $sort, $collection)
    {
        $this->sort = $sort;
        $this->tag = $tag;
        $this->collection = $collection;
        $this->navbar = 'Latest';
    }

    public function render()
    {
        $apis = $this->model::select('*');
        if(auth()->check() && auth()->user()->role != 'admin'){
            $apis = $apis->where('is_published', '!=', '0');
        }
        if($this->tag){
            $tags_id = ApihubTags::where('slug', $this->tag)->first();
            $apis = $apis->whereJsonContains('tags', $tags_id->id ?? 'invalid');
        }
        if($this->collection=='recommended'){
            $apis = $apis->where('is_recommended', 1);
        }
        if ($this->sort) {
            if($this->sort == 'old'){
                $apis = $apis->orderBy('created_at', 'desc');
                $this->navbar = 'Earliest';
            } else {
                $this->navbar = 'Latest';
                $apis = $apis->orderBy('created_at', 'asc');
            }
        } else {
            $this->navbar = 'Latest';
            $apis = $apis->orderBy('created_at', 'asc');
        }
        $data['apis'] = $apis->paginate($this->perPage);
        $data['tags'] = ApihubTags::all();
        return view('livewire.rapi', $data);
    }

    public function setTags($tag = null)
    {
        $this->resetPage();
        $this->tag = $tag;
        $this->emit('scrollToTop');
    }

    public function resetFilter(){
        $this->resetPage();
        $this->tag = null;
        $this->emit('scrollToTop');
    }
}
