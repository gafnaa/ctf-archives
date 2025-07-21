<?php

namespace App\Http\Controllers;

use App\Helpers\Layouts;
use App\Models\Apihub;
use App\Models\ApihubEndpoint;
use App\Models\ApihubTags;
use Illuminate\Http\Request;

class RapiController extends Controller
{
    public function index(){
        $data['seo'] = (object)[
            'title'=> 'API Hub - Public Rest APIs',
            'description'=> 'Browse Public Rest APIs in the Velixs API API Hub - API directory. Register today Free!',
            'image' => asset('assets/img/apis-thumbnail.jpg'),
        ];
        if(auth()->check() && auth()->user()->role == 'admin'){
            $data['latest'] = Apihub::orderBy('id','desc')->limit(12)->get();
        }else{
            $data['latest'] = Apihub::where('is_published','!=', 0)->orderBy('id','desc')->limit(12)->get();
        }
        $data['recommended'] = Apihub::where('is_published','!=', 0)->where('is_recommended','!=', 0)->orderBy('id','desc')->get();
        $data['tags'] = ApihubTags::all();
        return Layouts::view('rapi.index',$data);
    }

    public function detail($slug, Request $request){
        if(auth()->check() && auth()->user()->role == 'admin'){
            $api = Apihub::where('slug',$slug);
        }else{
            $api = Apihub::where('slug',$slug)->where('is_published','!=', 0);
        }
        if(!$api->exists()) return redirect()->route('rapi')->with('error','API not found');
        $api = $api->first();
        $data['seo'] = (object)[
            'title'=> $api->title,
            'description' => $api->meta_description,
            'image' => $api->thumbnail ? $api->_thumbnail() : $api->_image()
        ];
        $data['api'] = $api;
        if($request->segment(3) == 'lab'){
            $data['endpoints'] = ApihubEndpoint::where('apihub_id' , $api->id)->orderBy('created_at', 'asc')->get();
            return Layouts::view('rapi.lab',$data);
        } else {
            return Layouts::view('rapi.detail',$data);
        }
    }

    public function explore(Request $request){
        return Layouts::view('rapi.explore',[
            'tag' => $request->tag,
            'sort' => $request->sort,
            'collection' => $request->collection
        ]);
    }
}
