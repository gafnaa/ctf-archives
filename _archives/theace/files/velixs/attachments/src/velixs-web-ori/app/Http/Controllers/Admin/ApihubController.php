<?php

namespace App\Http\Controllers\Admin;

use App\Helpers\Layouts;
use App\Http\Controllers\Controller;
use App\Models\Apihub;
use App\Models\ApihubEndpoint;
use App\Models\ApihubTags;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Cache;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

class ApihubController extends Controller
{
    public function index(){
        return Layouts::view('admin.rapi.index');
    }

    public function json(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.rapi.index');
        $table = Apihub::orderBy('created_at', 'desc')->get();
        return datatables()->of($table)
            ->addColumn('apihub', function($row){
                return '<div class="d-flex justify-content-start align-items-center user-name"><div class="avatar-wrapper"><div class="avatar me-2"><img src="'.$row->_image().'" alt class="rounded" style="object-fit: cover;object-position: center;"></div></div><div class="d-flex flex-column"><span class="emp_name text-truncate">'.$row->title.'</span><small class="emp_post text-truncate text-muted">author : '.$row->_author->username.'</small></div></div>';
            })
            ->addColumn('status', function($row){
                switch($row->is_published){
                    case 1:
                        return '<span class="badge bg-label-success">active</span>';
                        break;
                    case 2:
                        return '<span class="badge bg-label-warning">Maintenance</span>';
                        break;
                    case 0:
                        return '<span class="badge bg-label-secondary">Draft</span>';
                        break;
                    default:
                        return '<span class="badge bg-label-secondary">-</span>';
                        break;
                }
            })
            ->editColumn('updated_at', function($row){
                return $row->updated_at->diffForHumans();
            })
            ->editColumn('action', function($row){
                return '<div class="d-inline-block"><a href="javascript:;" class="btn btn-sm btn-icon dropdown-toggle hide-arrow" data-bs-toggle="dropdown"><i class="text-primary ti ti-dots-vertical"></i></a>'.
                '<ul class="dropdown-menu dropdown-menu-end m-0"><li><a href="'.route("admin.rapi.endpoint", ["id" => $row->id]).'" class="dropdown-item itable-btn-detail">Manage Endpoint</a></li></ul>'.
                '</div>'.
                '<a href="'.route('admin.rapi.edit',$row->id).'" class="btn btn-sm btn-icon item-edit itable-btn-edit"><i class="text-primary ti ti-pencil"></i></a>';
            })
            ->rawColumns(['apihub', 'status', 'action'])
            ->make(true);
    }

    public function ajax_gslug_unique(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.rapi.index');
        do {
            $random = Layouts::generateUniqueSlug(7);
            $table = Apihub::where('slug', $random)->exists();
        } while($table);

        return response()->json([
            'slug' => $random
        ]);
    }

    public function create(){
        $tags = [];
        foreach(ApihubTags::all() as $tag){
            $tags[] = $tag->title;
        }
        $tags = json_encode($tags);
        return Layouts::view('admin.rapi.create',[
            'tags' => $tags
        ]);
    }

    public function store(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.rapi.index');
        $request->validate([
            'title' => 'required|string|max:255',
            'slug' => 'required|string|max:255|unique:apihubs',
            'image' => 'required|image|mimes:jpeg,png,jpg,gif,svg',
            'tags' => 'required',
            'is_published' => 'required',
            'readme' => 'required',
            'meta_description' => 'required|string',
        ]);
        try {
            $table = new Apihub();
            $table->title = $request->title;
            $table->slug = $request->slug;
            $table->is_published = $request->is_published;
            $table->author = auth()->id();
            $table->readme = $request->readme;
            $table->meta_description = $request->meta_description;
            $image = $request->file('image')->store('apis');
            $table->image = $image;
            $tags = [];
            foreach(json_decode($request->tags) as $tag){
                $btag = ApihubTags::firstOrCreate(['title' => $tag->value],[
                    'title' => $tag->value,
                    'slug' => trim(strtolower(str_replace(' ', '-', $tag->value))),
                ])->id;
                $tags[] = $btag;
            }
            $table->tags = $tags;
            $table->save();
        } catch (Exception $e){
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }

        return response()->json([
            'status' => 'success',
            'message' => 'Api created successfully',
            'redirect_edit' => route('admin.rapi.edit', $table->id)
        ]);
    }

    public function edit($id){
        $table = Apihub::find($id);
        if(!$table) return redirect()->route('admin.rapi.index')->with('info', 'Api not found.');
        // show tags
        $tags = [];
        foreach(ApihubTags::all() as $tag){
            $tags[] = $tag->title;
        }

        return Layouts::view('admin.rapi.edit',[
            'row' => $table,
            'tags' => json_encode($tags)
        ]);
    }

    public function update(Request $request, $id){
        if(!$request->ajax()) return redirect()->route('admin.rapi.index');

        $table = Apihub::find($id);
        if(!$table) return response()->json([
            'message' => 'Api not found.'
        ], 404);

        $request->validate([
            'title' => 'required|string|max:255',
            'slug' => 'required|string|max:255|unique:apihubs,slug,'.$table->id,
            'image' => 'nullable|image|mimes:jpeg,png,jpg,gif,svg',
            'tags' => 'required',
            'is_published' => 'required',
            'readme' => 'required',
            'meta_description' => 'required|string',
        ]);

        try{
            $table->title = $request->title;
            $table->slug = $request->slug;
            $table->is_published = $request->is_published;
            // $table->author = auth()->id();
            $table->readme = $request->readme;
            $table->meta_description = $request->meta_description;
             // image
             if($request->hasFile('image')){
                if($table->image) Storage::delete($table->image);
                $image = $request->file('image')->store('apis');
                $table->image = $image;
            }
            // tags
            $tags = [];
            foreach(json_decode($request->tags) as $tag){
                $btag = ApihubTags::firstOrCreate(['title' => $tag->value],[
                    'title' => $tag->value,
                    'slug' => trim(strtolower(str_replace(' ', '-', $tag->value))),
                ])->id;
                $tags[] = $btag;
            }
            $table->tags = $tags;
            $table->save();
        }catch (Exception $e){
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }

        return response()->json([
            'status' => 'success',
            'message' => 'Api updated successfully',
        ]);
    }

    public function syncThumbnail(Request $request, $id){
        if(!$request->ajax()) return redirect()->route('admin.rapi.index');
        $table = Apihub::find($id);
        if(!$table) return response()->json([
            'message' => 'Api not found.'
        ], 404);

        try{
            $client = new Client();
            $res = $client->post(rtrim(config('app.api_velixs_endpoint'), '/').'/card/thumb', [
                'form_params' => [
                    'avatar' => $table->_image(),
                    'title' => $table->title,
                    'description' => $table->meta_description,
                    'footer' => route('rapi.detail', $table->slug),
                    'logo' => 'https://velixs.com/storage/web/logo.svg'
                ],
                'headers' => [
                    'X-VelixsAPI-Key' => config('app.api_velixs_apikey')
                ]
            ]);

            $responseData = $res->getBody()->getContents();
            $uniqueName = 'apis/'.uniqid() . '-thumbnail.jpg';
            if($table->thumbnail){
                Storage::delete($table->thumbnail);
            }
            Storage::disk('public')->put($uniqueName, $responseData);

            $table->thumbnail = $uniqueName;
            $table->save();

            return response()->json([
                'status' => 'success',
                'message' => 'Thumbnail updated successfully',
                'data' => [
                    'preview' => asset('storage/'.$uniqueName),
                ]
            ]);
        }catch (RequestException $e){
            return response()->json(json_decode($e->getResponse()->getBody()->getContents()), 500);
        }
    }

    public function destroy(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.rapi.index');
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;
        $api = Apihub::whereIn('id', $ids);
        foreach($api->get() as $a){
            if($a->image) Storage::delete($a->image);
            ApihubEndpoint::where('apihub_id', $a->id)->delete();
        }
        $api->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'Apis deleted successfully'
        ]);
    }

    // endpoint controller

    public function ep($id){
        $api = Apihub::find($id);
        if(!$api) return redirect()->route('admin.rapi.index')->with('info', 'Api not found.');
        $data['api'] = $api;
        return Layouts::view('admin.rapi.ep.index', $data);
    }

    public function ep_json(Request $request, $id){
        if(!$request->ajax()) return redirect()->route('admin.rapi.endpoint');
        $table = ApihubEndpoint::where('apihub_id', $id)->orderBy('created_at', 'desc')->get();
        return datatables()->of($table)
            ->addColumn('action', function($row){
                return '<a href="'.route('admin.rapi.endpoint.edit', ['id' => $row->apihub_id, 'epid' => $row->id]).'" class="btn btn-sm btn-icon item-edit itable-btn-edit"><i class="text-primary ti ti-pencil"></i></a>';
            })
            ->rawColumns(['action'])
            ->make(true);
    }

    public function ep_create(Request $request, $id){
        $api = Apihub::find($id);
        if(!$api) return redirect()->route('admin.rapi.index')->with('info', 'Api not found.');
        $data['api'] = $api;
        return Layouts::view('admin.rapi.ep.create', $data);
    }

    public function ep_store(Request $request, $id){
        if(!$request->ajax()) return redirect()->route('admin.rapi.endpoint', $id);
        $request->validate([
            'title' => 'required|string',
            'method' => 'required|string',
            'url' => 'required|string',
        ]);
        try {
            $table = new ApihubEndpoint();
            $table->apihub_id = $id;
            $table->title = $request->title;
            $table->method = $request->method;
            $table->url = $request->url;
            $table->data = json_encode(json_decode($request->data_body));
            $table->response = json_encode(json_decode($request->data_response));
            $table->save();

            return response()->json([
                'status' => 'success',
                'message' => 'Api created successfully',
                'redirect_edit' => route('admin.rapi.endpoint.edit', ['id' => $id, 'epid'=>$table->id])
            ]);
        } catch (Exception $e){
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function ep_edit(Request $request, $id, $epid){
        $api = Apihub::find($id);
        if(!$api) return redirect()->route('admin.rapi.index')->with('info', 'Api not found.');
        $data['api'] = $api;
        $data['ep'] = ApihubEndpoint::find($epid);
        return Layouts::view('admin.rapi.ep.edit', $data);
    }

    public function ep_update(Request $request, $id, $epid){
        if(!$request->ajax()) return redirect()->route('admin.rapi.endpoint', $id);
        $request->validate([
            'title' => 'required|string',
            'method' => 'required|string',
            'url' => 'required|string',
        ]);

        try {
            $table = ApihubEndpoint::find($epid);
            $table->title = $request->title;
            $table->method = $request->method;
            $table->url = $request->url;
            $table->data = json_encode(json_decode($request->data_body));
            $table->response = json_encode(json_decode($request->data_response));
            $table->save();

            return response()->json([
                'status' => 'success',
                'message' => 'Api updated successfully'
            ]);
        } catch (Exception $e){
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function ep_destroy(Request $request, $id){
        if(!$request->ajax()) return redirect()->route('admin.rapi.endpoint', $id);
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;
        ApihubEndpoint::whereIn('id', $ids)->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'Api endpoints deleted successfully'
        ]);
    }


    // plan controller

    public function plan_index(){
        return Layouts::view('admin.rapi.plan.index');
    }

    public function plan_create(Request $request){
        if($request->isMethod('POST') && $request->ajax()){
            try{
                $client = new Client();
                $response = $client->post(rtrim(config('app.api_velixs_endpoint'), '/').'/velixs/plan',[
                    'headers' => [
                        'Content-Type' => 'application/json',
                        'X-Secret-Key' => config('app.api_velixs_secret'),
                        'X-Wow' => config('app.api_velixs_wow')
                    ],
                    'body' => json_encode(array(
                        "plan" => $request->plan,
                        "max_request" => $request->max_request,
                        "price" => $request->price,
                        "pricing" => array(
                            "button" => array(
                                "title" => $request->button_title,
                                "url" => $request->button_url
                            ),
                            "list" => $request->listinclude
                        )
                    ))
                ]);
                $res = json_decode($response->getBody()->getContents());
                Cache::forget('pricings');
                return response()->json([
                    'status' => 'success',
                    'message' => $res->message ?? 'Plan created successfully',
                    'redirect_edit' => route('admin.plan.edit',$res->data->id)
                ]);
            }catch(Exception $e){
                return response()->json([
                    'message' => $e->getMessage()
                ], 500);
            }
        } else {
            return Layouts::view('admin.rapi.plan.create');
        }
    }

    public function plan_edit(Request $request, $id){
        if($request->isMethod('POST') && $request->ajax()){
            try{
                $client = new Client();
                $response = $client->put(rtrim(config('app.api_velixs_endpoint'), '/').'/velixs/plan/'.$id,[
                    'headers' => [
                        'Content-Type' => 'application/json',
                        'X-Secret-Key' => config('app.api_velixs_secret'),
                        'X-Wow' => config('app.api_velixs_wow')
                    ],
                    'body' => json_encode(array(
                        "plan" => $request->plan,
                        "max_request" => $request->max_request,
                        "price" => $request->price,
                        'default_plan'=> $request->default==1 ? true : false,
                        "pricing" => array(
                            "button" => array(
                                "title" => $request->button_title,
                                "url" => $request->button_url
                            ),
                            "list" => $request->listinclude
                        )
                    ))
                ]);
                $res = json_decode($response->getBody()->getContents());
                Cache::forget('pricings');
                return response()->json([
                    'status' => 'success',
                    'message' => $res->message ?? 'Plan updated successfully',
                ]);
            }catch(Exception $e){
                return response()->json([
                    'message' => $e->getMessage()
                ], 500);
            }
        } else {
            try{
                $client = new Client();
                $response = $client->get(rtrim(config('app.api_velixs_endpoint'), '/').'/velixs/plan/'.$id,[
                    'headers' => [
                        'Content-Type' => 'application/json',
                        'X-Secret-Key' => config('app.api_velixs_secret'),
                        'X-Wow' => config('app.api_velixs_wow')
                    ]
                ]);
                $res = json_decode($response->getBody()->getContents());
                $data['plan'] = $res[0];
                return Layouts::view('admin.rapi.plan.edit', $data);
            }catch(Exception $e){
                return response()->json([
                    'message' => $e->getMessage()
                ], 500);
            }
        }
    }

    public function plan_delete(Request $request){
        if($request->ajax()){
            try{
                $client = new Client();
                $response = $client->delete(rtrim(config('app.api_velixs_endpoint'), '/').'/velixs/plan',[
                    'headers' => [
                        'Content-Type' => 'application/json',
                        'X-Secret-Key' => config('app.api_velixs_secret'),
                        'X-Wow' => config('app.api_velixs_wow')
                    ],
                    'body' => json_encode(array(
                        "id" => $request->ids
                    ))
                ]);
                $res = json_decode($response->getBody()->getContents());
                Cache::forget('pricings');
                return response()->json([
                    'status' => 'success',
                    'message' => $res->message ?? 'Plan deleted successfully',
                ]);
            }catch(Exception $e){
                return response()->json([
                    'message' => $e->getMessage()
                ], 500);
            }
        }
    }
}
