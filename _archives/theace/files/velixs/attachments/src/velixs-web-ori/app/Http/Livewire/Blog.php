<?php

namespace App\Http\Livewire;

use Livewire\Component;
use Livewire\WithPagination;
use App\Models\Blog as BlogModel;
use App\Models\BlogTags;

class Blog extends Component
{
    use WithPagination;

    protected $model = BlogModel::class;
    protected $perPage = 10;
    public $tags = null;
    public $sort = null;
    public $navbar;
    protected $queryString = [
        'tags' => ['except' => null]
    ];

    public function mount($sort, $tags)
    {
        $this->sort = $sort;
        $this->tags = $tags;
        $this->navbar = 'Latest';
    }

    public function render()
    {
        $blogs = $this->model::select('*');
        $blogs = $blogs->where('is_published', '!=', '0');
        if($this->tags){
            $tags_id = BlogTags::where('slug', $this->tags)->first();
            $blogs = $blogs->whereJsonContains('tags', $tags_id->id ?? 'invalid');
        }
        if ($this->sort) {
            if($this->sort == 'popular'){
                $blogs = $blogs->withCount('traffic')->orderBy('traffic_count', 'desc');
                $this->navbar = 'Popular';
            } else if ($this->sort == 'trending'){
                $blogs = $blogs->withCount(['traffic' => function ($query) {
                    $query->where('created_at', '>=', now()->subDays(7));
                }])->orderBy('traffic_count', 'desc');
                $this->navbar = 'Trending';
            } else if ($this->sort == 'popular-month'){
                $this->navbar = 'Popular This Month';
                $blogs = $blogs->withCount(['traffic' => function ($query) {
                    $query->where('created_at', '>=', now()->subDays(30));
                }])->orderBy('traffic_count', 'desc');
            } else {
                $this->navbar = 'Latest';
                $blogs = $blogs->orderBy('created_at', 'desc');
            }
        } else {
            $this->navbar = 'Latest';
            $blogs = $blogs->orderBy('created_at', 'desc');
        }

        $blogs = $blogs->paginate($this->perPage);
        return view('livewire.blog',[
            'navbar_active' => $this->navbar, // 'Latest', 'Popular', 'Trending', 'Popular This Month
            'blogs' => $blogs,
            'perPage' => $this->perPage,
        ]);
    }

    public function setTags($tags = null)
    {
        $this->resetPage();
        $this->tags = $tags;
        $this->emit('scrollToTop');
    }

    public function resetFilter(){
        $this->resetPage();
        $this->tags = null;
        $this->emit('scrollToTop');
    }

}
