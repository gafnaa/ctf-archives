<?php

namespace App\Http\Controllers\Admin;

use App\Helpers\Layouts;
use App\Http\Controllers\Controller;
use App\Models\waGroup;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Storage;

class WAProgrammerController extends Controller
{
    public function index(){
        return Layouts::view('admin.wagroup.index');
    }

    public function json(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.wagroup.index');
        $table = waGroup::all();
        return datatables()->of($table)
            ->addColumn('whatsapp', function($row){
                return '<div class="d-flex justify-content-start align-items-center user-name"><div class="avatar-wrapper"><div class="avatar me-2"><img src="'.$row->_image().'" alt="Avatar" class="rounded-circle"></div></div><div class="d-flex flex-column"><a href="'.$row->whatsapp_url.'" class="emp_name text-truncate">'.htmlspecialchars($row->name).'</a><small class="emp_post text-truncate text-muted"></small></div></div>';
            })
            ->editColumn('status', function($row){
                $s = [];
                if($row->status == 'published'){
                    $s = [
                        'class' => 'info',
                        'text' => 'Published'
                    ];
                } else if ($row->status == 'pending') {
                    $s = [
                        'class' => 'warning',
                        'text' => 'Pending'
                    ];
                } else {
                    $s = [
                        'class' => 'secondary',
                        'text' => 'Draft'
                    ];
                }

                return '<div class="btn-group">
                <span type="button" class="badge bg-label-'.$s['class'].' dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
                    '.$s['text'].'
                </span>
                <ul class="dropdown-menu" style="">
                  <li><a data-id="'.$row->id.'" data-status="published" class="dropdown-item __btn_switch_status" href="javascript:void(0);">Published</a></li>
                  <li><a data-id="'.$row->id.'" data-status="pending" class="dropdown-item __btn_switch_status" href="javascript:void(0);">Pending</a></li>
                  <li><a data-id="'.$row->id.'" data-status="draft" class="dropdown-item __btn_switch_status" href="javascript:void(0);">Draft</a></li>
                </ul>
              </div>';
            })
            ->rawColumns(['whatsapp','status'])
            ->make(true);
    }

    public function toggle_status(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.wagroup.index');
        $request->validate([
            'id' => 'required|integer',
            'status' => 'required|string|in:published,pending,draft'
        ]);

        $table = waGroup::find($request->id);
        $table->status = $request->status;
        $table->save();

        return response()->json([
            'status' => 'success',
            'message' => 'Status updated successfully'
        ]);
    }

    public function destroy(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.wagroup.index');
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;
        $table = waGroup::whereIn('id', $ids);
        foreach($table->get() as $row){
            if($row->image){ Storage::delete($row->image); }
        }
        $table->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'Group deleted successfully'
        ]);
    }


    public function sync(Request $request){
        $client = new Client();
        $table = waGroup::all();
        foreach($table as $row){
            try{
                $res = $client->get(rtrim(config('app.api_velixs_endpoint'), '/').'/whatsapp-group?url='.$row->whatsapp_url, [
                    'headers' => [
                        'Content-Type' => 'application/json',
                        'X-VelixsAPI-Key' => config('app.api_velixs_apikey')
                    ]
                ]);
                $http = json_decode($res->getBody()->getContents(), true);
                $group = waGroup::find($row->id);
                $group->name = $http['data']['title'];
                $image = file_get_contents($http['data']['image']);
                if($row->image){ Storage::delete($row->image); }
                $imageName = 'wa-group-'.Str::random(10).'.jpg';
                Storage::disk('public')->put('wagroup/'.$imageName, $image);
                $group->image = 'wagroup/'.$imageName;
                $group->save();
            }catch(RequestException $e){
                if(json_decode($e->getResponse()->getBody()->getContents())->message=='group not found'){
                    waGroup::destroy($row->id);
                }
            }
        }

        return response()->json([
            'status' => true,
            'message' => 'Group updated successfully'
        ]);
    }

}
