<?php

namespace App\Http\Livewire;

use App\Models\Product as ModelsProduct;
use App\Models\ProductTags;
use Livewire\Component;
use Livewire\WithPagination;

class Product extends Component
{
    use WithPagination;

    protected $model = ModelsProduct::class;
    protected $perPage = 12;
    public $tags = null;
    protected $queryString = [
        'tags' => ['except' => null]
    ];

    public function mount($tags)
    {
        $this->tags = $tags;
    }

    public function render()
    {
        $product = $this->model::select('*');
        if($this->tags){
            $tags_id = ProductTags::where('slug', $this->tags)->first();
            $product = $product->whereJsonContains('tags', $tags_id->id ?? 'invalid');
        }
        $product = $product->where('is_published','!=', 0);
        $product = $product->orderBy('created_at', 'desc');
        $product = $product->paginate($this->perPage);
        return view('livewire.product',[
            'products' => $product,
            'perPage' => $this->perPage,
            'product_tags' => ProductTags::all(),
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
