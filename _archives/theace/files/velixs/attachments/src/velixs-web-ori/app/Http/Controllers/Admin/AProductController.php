<?php

namespace App\Http\Controllers\Admin;

use App\Helpers\Layouts;
use App\Http\Controllers\Controller;
use App\Models\Product;
use App\Models\ProductTags;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class AProductController extends Controller
{
    public function index(){
        return Layouts::view('admin.product.index',[
            'type' => 'all'
        ]);
    }

    public function trash(){
        return Layouts::view('admin.product.trash',[
            'type' => 'onlytrashed'
        ]);
    }

    public function trash_recovery(Request $request,$id){
        if(!$request->ajax()) return redirect()->route('admin.product.index');
        Product::onlyTrashed()->where('id', $id)->restore();
        return response()->json([
            'status' => 'success',
            'message' => 'Product restored successfully'
        ]);
    }

    public function json(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.product.index');
        if($request->type == 'onlytrashed'){
            $product = Product::onlyTrashed()->get();
        } else {
            $product = Product::all();
        }
        return datatables()->of($product)
            ->editColumn('title', function($product){
                return '<div class="d-flex justify-content-start align-items-center user-name"><div class="avatar-wrapper"><div class="avatar me-2" style="width: 3rem;"><img src="'.$product->_image().'" alt class="rounded" style="object-fit: cover;object-position: center;"></div></div><div class="d-flex flex-column"><span class="emp_name text-truncate">'.$product->title.'</span><small class="emp_post text-truncate text-muted">Latest Version '.$product->_latestRelease().'</small></div></div>';
            })
            ->addColumn('views', function($product){
                return $product->_countViewShort();
            })
            ->editColumn('is_published', function($product){
                // return $product->is_published  ? '<span class="badge bg-label-primary">Published</span>' : '<span class="badge bg-label-secondary">Draft</span>';
                switch($product->is_published){
                    case 1:
                        return '<span class="badge bg-label-primary">Published</span>';
                        break;
                    case 2:
                        return '<span class="badge bg-label-warning">Archived</span>';
                        break;
                    case 0:
                        return '<span class="badge bg-label-secondary">Draft</span>';
                        break;
                    default:
                        return '<span class="badge bg-label-secondary">-</span>';
                        break;
                }
            })
            ->addColumn('deleted_at', function($product){
                return $product->deleted_at ? $product->deleted_at->format('M d, Y') : '';
            })
            ->addColumn('updated_at', function($product){
                return $product->updated_at->format('M d, Y');
            })
            ->addColumn('price', function($product){
                return $product->_isFree() ? '<span class="badge bg-label-success">Free</span>' : '<span class="badge bg-label-primary">Paid</span>';
            })
            ->rawColumns(['title', 'is_published', 'price', 'action'])
            ->make(true);
    }

    public function destroy(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.product.index');
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;
        Product::whereIn('id', $ids)->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'Product deleted successfully'
        ]);
    }

    public function destroy_force(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.product.index');
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;

        $product = Product::onlyTrashed()->whereIn('id', $ids);
        foreach($product->get() as $p){
            if($p->image) Storage::delete($p->image);
        }
        $product->forceDelete();

        return response()->json([
            'status' => 'success',
            'message' => 'Product deleted permanently'
        ]);
    }

    public function create(){
        $tags = [];
        foreach(ProductTags::all() as $tag){
            $tags[] = $tag->title;
        }
        $tags = json_encode($tags);
        return Layouts::view('admin.product.create',[
            'tags' => $tags
        ]);
    }

    public function store(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.product.index');
        $request->validate([
            'title' => 'required|string|max:255',
            'slug' => 'required|string|max:255|unique:products',
            'image' => 'required|image|mimes:jpeg,png,jpg,gif,svg|max:2048',
            'tags' => 'required',
            'is_published' => 'required',
            'content' => 'required',
            'product_type' => 'required',
        ]);

        if($request->product_type == 'pay'){
            $request->validate([
                'price_usd' => 'required',
                'price_idr' => 'required',
            ]);
            $request->github = null;
        }

        $product = new Product();
        $product->title = $request->title;
        $product->slug = $request->slug;
        $product->content = $request->content;
        // image
        $image = $request->file('image')->store('item');
        $product->image = $image;
        // tags
        $tags = [];
        foreach(json_decode($request->tags) as $tag){
            $producttag = ProductTags::firstOrCreate(['title' => $tag->value],[
                'title' => $tag->value,
                'slug' => trim(strtolower(str_replace(' ', '-', $tag->value))),
            ])->id;
            $tags[] = $producttag;
        }
        $product->github = $request->github;
        $product->is_free = $request->product_type == 'free' ? true : false;
        $product->tags = $tags;
        $product->is_published = $request->is_published;
        $product->author = auth()->id();
        $product->meta_description = substr(strip_tags($request->content), 0, 160);
        $product->preview = $request->preview;
        $product->price = array(
            'usd' => $request->product_type == 'pay' ? $request->price_usd : 0,
            'idr' => $request->product_type == 'pay' ? $request->price_idr : 0,
        );
        $product->save();

        return response()->json([
            'status' => 'success',
            'message' => 'Product created successfully',
            'redirect_edit' => route('admin.product.edit', $product->id)
        ]);
    }

    public function edit($id){
        $product = Product::find($id);
        if(!$product) return redirect()->route('admin.product.index')->with('info', 'Product not found.');
        // show tags
        $tags = [];
        foreach(ProductTags::all() as $tag){
            $tags[] = $tag->title;
        }

        return Layouts::view('admin.product.edit',[
            'product' => $product,
            'tags' => json_encode($tags)
        ]);
    }

    public function update(Request $request, $id){
        if(!$request->ajax()) return redirect()->route('admin.product.index');

        $product = Product::find($id);
        if(!$product) return response()->json([
            'message' => 'Product not found.'
        ], 404);

        $request->validate([
            'title' => 'required|string|max:255',
            'slug' => 'required|string|max:255|unique:products,slug,'.$product->id,
            'image' => 'nullable|image|mimes:jpeg,png,jpg,gif,svg|max:2048',
            'tags' => 'required',
            'is_published' => 'required',
            'meta_description' => 'nullable|string|max:160',
            'content' => 'required',
            'product_type' => 'required',
        ]);


        if($request->product_type == 'pay'){
            $request->validate([
                'price_usd' => 'required',
                'price_idr' => 'required',
            ]);
            $request->github = null;
        }

        $product->title = $request->title;
        $product->slug = $request->slug;
        $product->content = $request->content;
        // image
        if($request->hasFile('image')){
            if($product->image) Storage::delete($product->image);
            $image = $request->file('image')->store('item');
            $product->image = $image;
        }
        // tags
        $tags = [];
        foreach(json_decode($request->tags) as $tag){
            $producttag = ProductTags::firstOrCreate(['title' => $tag->value],[
                'title' => $tag->value,
                'slug' => trim(strtolower(str_replace(' ', '-', $tag->value))),
            ])->id;
            $tags[] = $producttag;
        }
        $product->github = $request->github;
        $product->is_free = $request->product_type == 'free' ? true : false;
        $product->tags = $tags;
        $product->is_published = $request->is_published;
        // $product->author = auth()->id();
        $product->meta_description = $request->meta_description;
        $product->preview = $request->preview;
        $product->price = array(
            'usd' => $request->product_type == 'pay' ? $request->price_usd : 0,
            'idr' => $request->product_type == 'pay' ? $request->price_idr : 0,
        );
        $product->save();

        return response()->json([
            'status' => 'success',
            'message' => 'Product updated successfully',
        ]);
    }

    public function release($id){
        $product = Product::find($id);
        if(!$product) return redirect()->route('admin.product.index')->with('info', 'Product not found.');
        $data['product'] = $product;
        return Layouts::view('admin.product.release',$data);
    }

    public function release_update(Request $request,$id){
        if(!$request->ajax()) return redirect()->route('admin.product.release', $id);
        $product = Product::find($id);
        if(!$product) return response()->json([
            'message' => 'Product not found.'
        ], 404);

        $request->validate([
            'latest_version' => 'required|string|max:255',
            'latest_url' => 'required|string|max:255',
        ]);

        $archive = array();

        if($request->has('archive_version')){
            foreach($request->archive_version as $key => $version){
                $archive[] = array(
                    'version' => $version,
                    'url' => $request->archive_url[$key],
                );
            }
        }

        $release = array(
            'latest' => $request->latest_version,
            'latest_url'=> $request->latest_url,
            'archive' => $archive
        );

        $product->release = $release;
        $product->save();

        return response()->json([
            'status' => 'success',
            'message' => 'Product updated successfully',
            'data' => $release,
        ]);
    }

    public function release_force(Request $request, $id){
        $product = Product::find($id);
        if(!$product) return redirect()->route('admin.product.index')->with('info', 'Product not found.');

        $product->release = null;
        $product->save();

        return redirect()->route('admin.product.release', $id)->with('success', 'Product release deleted successfully');
    }

    public function tags_index(Request $request){
        if($request->ajax()){
            $tags = ProductTags::all();
            return datatables()->of($tags)
                // ->rawColumns(['action'])
                ->make(true);
        } else {
            return Layouts::view('admin.product.tags');
        }
    }

    public function tags_create(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.product.tags');
        $request->validate([
            'title' => 'required|string|max:255|unique:product_tags',
            'slug' => 'required|string|max:255|unique:product_tags',
        ]);

        $tag = new ProductTags();
        $tag->title = $request->title;
        $tag->slug = $request->slug;
        $tag->save();

        return response()->json([
            'status' => 'success',
            'message' => 'Product tags created successfully'
        ]);
    }

    public function tags_destroy(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.product.tags');
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;
        ProductTags::whereIn('id', $ids)->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'Product tags deleted successfully'
        ]);
    }

    public function tags_edit(Request $request,$id){
        if(!$request->ajax()) return redirect()->route('admin.product.tags');
        $tag = ProductTags::find($id);
        if(!$tag) return response()->json([
            'message' => 'Product tags not found.'
        ], 404);
        return response()->json([
            'status' => 'success',
            'data' => $tag
        ]);
    }

    public function tags_update(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.product.tags');
        $tag = ProductTags::find($request->id);
        if(!$tag) return response()->json([
            'message' => 'Product tags not found.'
        ], 404);

        $request->validate([
            'title' => 'required|string|max:255|unique:product_tags,title,'.$tag->id,
            'slug' => 'required|string|max:255|unique:product_tags,slug,'.$tag->id,
        ]);

        $tag->title = $request->title;
        $tag->slug = $request->slug;
        $tag->save();

        return response()->json([
            'status' => 'success',
            'message' => 'Product tags updated successfully'
        ]);
    }
}
