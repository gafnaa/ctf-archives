<?php

namespace App\Http\Controllers;

use App\Helpers\Layouts;
use App\Models\Blog;
use App\Models\License;
use App\Models\Product;
use App\Models\User;
use App\Models\waGroup;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Support\Facades\Cache;

class MainController extends Controller
{
    use DispatchesJobs;
    public function index(Request $request){
        $data['seo'] = (object)[
            'title'=> 'VELIXS',
        ];
        $data['blog_latest'] = Blog::orderBy('id', 'desc')->limit(3)->get();
        return Layouts::view('main/landing',$data);
    }

    public function license_direct(Request $request){
        $args = $request->segment(1);
        $license = License::where('license_key', str_replace("@","",$args))->first();
        if(!$license) return redirect()->route('main')->with('bug', 'License key not found.');
        $data['seo'] = (object)[
            'title'=> 'VELIXS',
        ];
        $data['blog_latest'] = Blog::orderBy('id', 'desc')->limit(3)->get();
        $data['license_get'] = $license;
        return Layouts::view('main/landing',$data);
    }

    public function sus(Request $request){
        if(!auth()->check()) return redirect()->route('main');
        if(!auth()->user()->suspended) return redirect()->route('main');
        return view('main.sus',[
            'message' => auth()->user()->suspended,
        ]);
    }

    public function contact(){
        return Layouts::view('main/contact',[
            'seo' => (object)[
                'title'=> 'Contact Us',
            ]
        ]);
    }

    public function search(Request $request) {
        $search = $request->get('q');
        $result = null;
        $result['for'] = 'lol';
        $result['result'] = null;
        $result['error'] = false;
        if($search){
            if(Str::startsWith($search, '#')){
                $result['for'] = 'license';
                if (RateLimiter::tooManyAttempts('search-license:'.$request->ip(), 5)) {
                    $result['error'] = '<span class="font-semibold" style="color:#f30c0cba">Spam detected</span>, please try again later.';
                }else{
                    $search = substr(str_replace(" ","",$search), 1);
                    if(strlen($search) >= 1){
                        // RateLimiter::hit('search-license:'.$request->ip());
                        $getlicense = License::where('license_key', $search)->first();
                        if($getlicense){
                            $result['result'] = [
                                'url'=> route('dash.license', $getlicense->id),
                                'item'=> $getlicense->_item->title,
                            ];
                        } else {
                            $result['error'] = 'The license you entered does not match.';
                        }
                    } else {
                        $result['error'] = 'Example: #LICENSE-XXX-XXX-XXX-XXX';
                    }
                }
            } else {
                $result['for'] = 'search';
                $result['result'] = [];
                $product = Product::where('title', 'like', '%'.$search.'%')->limit(5)->get();
                foreach($product as $p){
                    $result['result'][] = [
                        'title' => $p->title,
                        'url' => route('product.detail', $p->slug),
                        'type' => 'item',
                    ];
                }
                $blog = Blog::where('title', 'like', '%'.$search.'%')->limit(5)->get();
                foreach($blog as $b){
                    $result['result'][] = [
                        'title' => $b->title,
                        'url' => route('blog.detail', $b->slug),
                        'type' => 'blog',
                    ];
                }
            }
        }
        return response()->json($result);
    }


    public function profile($username){
        $getuser = User::where('username', $username)->first();
        if(!$getuser) return redirect()->route('main')->with('info', 'User not found');
        return Layouts::view('main.profile',[
            'seo' => (object)[
                'title'=> $getuser->name,
                'description'=> '@username: '.$getuser->username. ' - '.$getuser->title_profile,
                'image'=> $getuser->_avatar(),
            ],
            'user' => $getuser,
        ]);
    }

    public function sitemap(){
        $xml = Storage::disk('public')->get('sitemap.xml');
        return response($xml, 200)->header('Content-Type', 'text/xml');
    }

    public function whatsappProgrammer(Request $request){
        if($request->isMethod('POST') && $request->ajax()){
            if(RateLimiter::tooManyAttempts('whatsapp-programmer-submit:'.$request->ip(), 5)) {
                return response()->json([
                    'status' => false,
                    'style' => 'bug',
                    'message' => 'Slow down, please try again later.',
                ], 429);
            } else {
                RateLimiter::hit('whatsapp-programmer-submit:'.$request->ip());
            }
            $request->validate([
                'url' => 'required',
            ]);
            $url = $request->url;
            $check = waGroup::where('whatsapp_url', $url)->first();
            if($check){
                if($check->status=='pending'){
                    return response()->json([
                        'status' => false,
                        'style' => 'warning',
                        'message' => 'Group sedang dalam proses review',
                    ], 409);
                } else {
                    return response()->json([
                        'status' => false,
                        'style' => 'warning',
                        'message' => 'Group already exist',
                    ], 409);
                }
            }
            try{
                $client = new Client();
                $res = $client->get(rtrim(config('app.api_velixs_endpoint'), '/').'/whatsapp-group?url='.$url, [
                    'headers' => [
                        'Content-Type' => 'application/json',
                        'X-VelixsAPI-Key' => config('app.api_velixs_apikey')
                    ]
                ]);
                $http = json_decode($res->getBody()->getContents(), true);
                $group = new waGroup();
                $group->whatsapp_url = $url;
                $group->name = $http['data']['title'];
                $image = file_get_contents($http['data']['image']);
                $imageName = 'wa-group-'.Str::random(10).'.jpg';
                Storage::disk('public')->put('wagroup/'.$imageName, $image);
                $group->image = 'wagroup/'.$imageName;
                $group->save();
                return response()->json([
                    'status' => true,
                    'style' => 'success',
                    'message' => 'Terimakasih sudah ikut berkontribusi, group akan kami review terlebih dahulu sebelum di publish',
                    'data' => $http['data'],
                ], 200);
            }catch(RequestException $e){
                return response()->json([
                    'status' => false,
                    'style' => 'error',
                    'message' => json_decode($e->getResponse()->getBody()->getContents())->message ?? 'Something went wrong',
                ], 500);
            }
        } else {
            return Layouts::view('main.waprogrammer',[
                'seo' => (object)[
                    'title'=> 'Kumpulan Group Whatsapp Programmer Indonesia',
                    'image'=> asset('assets/img/waprogrammer.jpg'),
                    'description'=> '60+ Groups',
                ],
                'groups' => waGroup::where('status', 'published')->get(),
            ]);
        }
    }

    public function pricing(){
        if(Cache::has('pricings')) {
            $data['pricings'] = Cache::get('pricings');
        } else {
            try {
                $client = new Client();
                $response = $client->get(rtrim(config('app.api_velixs_endpoint'), '/').'/velixs/plan',[
                    'headers' => [
                        'Content-Type' => 'application/json',
                        'X-Secret-Key' => config('app.api_velixs_secret'),
                        'X-Wow' => config('app.api_velixs_wow')
                    ]
                ]);
                $data['pricings'] = json_decode($response->getBody()->getContents(), true);
                Cache::forever('pricings', $data['pricings']);
            } catch(e) {
                $data['pricings'] = [];
            }
        }
        return Layouts::view('main.pricing', $data);
    }

    public function privacy(){
        return 'privacy';
    }

    public function tos(){
        return 'tos';
    }
}
