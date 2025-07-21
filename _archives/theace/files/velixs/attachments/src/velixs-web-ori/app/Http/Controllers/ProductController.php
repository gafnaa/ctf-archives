<?php

namespace App\Http\Controllers;

use App\Helpers\Layouts;
use App\Models\OwnedLicense;
use App\Models\Product;
use App\Models\ProductVisitor;
use App\Helpers\Referral;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\RateLimiter;

class ProductController extends Controller
{
    use DispatchesJobs;
    public function index(){
        $data['tags'] = request()->query('tags');
        $data['seo'] = (object)[
            'title' => 'Marketplace - Product',
            'description' => 'Discover a wide range of digital products tailored to your needs on our website. We offer a diverse selection of templates, plugins, scripts, and more. Find the perfect solutions for your projects with high-quality and user-friendly digital products. Explore our collection now and enhance your efficiency and creativity in developing digital projects.',
        ];
        return Layouts::view('product.index', $data);
    }

    public function show(Request $request, $slug){
        $item  = Product::where([
            'slug' => $slug,
            ['is_published', '!=', 0],
        ]);
        if(!$item->exists()) return abort(404);
        $item = $item->first();
        //hit visitor
        $user_id = auth()->id();
        $visitor = null;
        if($user_id){
            $visitor = ProductVisitor::where('product_id', $item->id)->where('user_id', $user_id);
        } else {
            $visitor = ProductVisitor::where('product_id', $item->id)->where('ip', $request->ip());
        }

        if(!$visitor->exists()){
            \App\Jobs\InsertVisitorProductJob::dispatch([
                'ip' => $request->ip(),
                'user_id' => $user_id,
                'product_id' => $item->id,
                'user_agent' => $request->userAgent(),
            ]);
        }

        $data['item'] = $item;
        $data['seo'] = (object)[
            'title' => $item->title,
            'description' => $item->meta_description,
            'image' => $item->_image(),
        ];
        $data['sales'] = Layouts::shortNumber(OwnedLicense::where([
            'item' => 'digital-product',
            'item_id' => $item->id,
        ])->count());

        Referral::handler($request->query('ref'));

        $data['page_product_detail'] = true;
        return Layouts::view('product.show', $data);
    }

    public function toggle_wishlist($slug) {
        if(!auth()->check()) return response()->json([
            'style' => 'info',
            'title' => 'Login required',
            'message' => 'Please login to add product to wishlist.'
        ]);
        if (RateLimiter::tooManyAttempts('wishlist-digital-product:'.auth()->id(), 5)) {
            return response()->json([
                'status' => 'bug',
                'title' => 'Bib bob 🤖',
                'message' => 'please slow down the request'
            ], 429);
        }
        if(!request()->ajax()) return abort(404);
        $product = Product::where('slug', $slug)->where('is_published', '!=', 0);
        if(!$product->exists()) return response()->json([
            'style' => 'error',
            'message' => 'Product not found.'
        ], 404);
        $product = $product->first();
        $user = auth()->user();
        $wishlist = $user->digital_product_wishlist;
        if(in_array($product->id, $wishlist)){
            $user->digital_product_wishlist = array_values(array_diff($wishlist, [$product->id]));
            $user->save();
            return response()->json([
                'style' => 'info',
                'title' => 'Wishlist removed',
                'message' => 'Product removed from wishlist.',
                'wishlist' => 'removed',
            ]);
        } else {
            $wishlist[] = $product->id;
            $user->digital_product_wishlist = $wishlist;
            $user->save();
            RateLimiter::hit('wishlist-digital-product:'.auth()->id());
            return response()->json([
                'style' => 'info',
                'title' => 'Wishlist added',
                'message' => 'Product added to wishlist.',
                'wishlist' => 'added',
            ]);
        }
    }

    // claim free
    public function claim($slug){
        if(!request()->ajax()) return abort(404);
        if (RateLimiter::tooManyAttempts('claim-digital-product:'.auth()->id(), 3)) {
            return response()->json([
                'style' => 'bug',
                'title' => 'Bib bob 🤖',
                'message' => 'please slow down the request'
            ], 429);
        }
        RateLimiter::hit('claim-digital-product:'.auth()->id());
        $product = Product::where([
            'slug' => $slug,
            ['is_published', '!=', 0],
        ]);

        if(!$product->exists()) return response()->json([
            'style' => 'info',
            'title' => 404,
            'message' => 'item not found.',
        ], 404);

        $product = $product->first();
        if(!$product->_isFree()) return response()->json([
            'style' => 'bug',
            'title' => 'Opps',
            'message' => 'item not free.',
        ], 404);

        if(!auth()->check()) return response()->json([
            'style' => 'info',
            'title' => 'Login required',
            'message' => 'Please login to claim item.'
        ], 404);

        $user = auth()->user();
        if($product->_hasOwned($user)) return response()->json([
            'style' => 'info',
            'title' => 'Already claimed',
            'message' => 'You already claimed this item.',
        ], 404);

        $license = OwnedLicense::create([
            'user_id' => $user->id,
            'item' => 'digital-product',
            'item_id' => $product->id,
            'license_key' => Layouts::MakeLicense('digital-product')
        ]);

        if(!$license) return response()->json([
            'style' => 'bug',
            'title' => 'Opps',
            'message' => 'Something went wrong.',
        ], 500);

        return response()->json([
            'style' => 'success',
            'title' => 'Claimed',
            'message' => 'Item added to your library.<br>Redirecting to library...',
        ]);
    }
}
