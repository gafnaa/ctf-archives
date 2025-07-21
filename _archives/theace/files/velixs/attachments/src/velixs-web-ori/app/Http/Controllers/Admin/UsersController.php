<?php

namespace App\Http\Controllers\Admin;

use App\Helpers\Layouts;
use App\Http\Controllers\Controller;
use App\Models\OwnedLicense;
use App\Models\User;
use Carbon\Carbon;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class UsersController extends Controller
{
    public function index(){
        return Layouts::view('admin.users.index');
    }


    public function json(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.users.index');
        $table = User::orderBy('created_at','desc')->get();
        return datatables()->of($table)
            ->addColumn('profile', function($row){
                return '<div class="d-flex justify-content-start align-items-center user-name"><div class="avatar-wrapper"><div class="avatar me-2"><img src="'.$row->_avatar().'" alt="Avatar" class="rounded-circle"></div></div><div class="d-flex flex-column"><a href="'.route('profile',$row->username).'" class="emp_name text-truncate">'.htmlspecialchars($row->name).'</a><small class="emp_post text-truncate text-muted">'.htmlspecialchars($row->username).'</small></div></div>';
            })
            ->editColumn('role',function($row){
                return $row->role == 'admin' ? '<span class="badge bg-label-danger">⚡ Admin</span>' : '<span class="badge bg-label-primary">User</span>';
            })
            ->editColumn('suspended',function($row){
                return $row->suspend ? '<span class="badge bg-label-danger">Suspended</span>' : '<span class="badge bg-label-success">-</span>';
            })
            ->editColumn('created_at',function($row){
                return $row->created_at->diffForHumans();
            })
            ->rawColumns(['profile','role','suspended'])
            ->make(true);
    }


    public function destroy(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.users.index');
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;
        $users = User::whereIn('id', $ids)->get();
        foreach($users as $user){
            try{
                $client = new Client();
                $client->delete(rtrim(config('app.api_velixs_endpoint'), '/').'/velixs/apikey/userid/'.$user->id,[
                    'headers' => [
                        'Content-Type' => 'application/json',
                        'X-Secret-Key' => config('app.api_velixs_secret'),
                        'X-Wow' => config('app.api_velixs_wow')
                    ]
                ]);
            }catch(\Exception $e){}

            if($user->avatar){
                Storage::delete($user->avatar);
            }
            OwnedLicense::where('user_id', $user->id)->delete();
            $user->delete();
        }

        return response()->json([
            'status' => 'success',
            'message' => 'Users deleted successfully.'
        ]);
    }

    public function edit($id){
        $user = User::find($id);
        if(!$user) return redirect()->route('admin.users.index')->with('error','User not found.');
        return Layouts::view('admin.users.edit', compact('user'));
    }

    public function update(Request $request, $id){
        if(!$request->ajax()) return redirect()->route('admin.users.index');
        $user = User::find($id);
        if(!$user) return response()->json([
            'status' => 'error',
            'message' => 'User not found.'
        ], 404);

        $request->validate([
            'name' => 'required|string|max:50',
            'email' => 'required|email|unique:users,email,'.$user->id,
            'username' => 'required|regex:/^[a-z0-9]+$/|max:255|unique:users,username,'.$user->id,
            'whatsapp' => 'max:30|unique:users,whatsapp,'.$user->id.'|nullable',
            'about' => 'max:255|nullable',
        ],[
            'username.regex' => 'Username can only contain letters and numbers'
        ]);

        if($request->new_password){
            $request->validate([
                'new_password' => 'required|string|min:8',
                'confirm-new-password' => 'required|string|same:new_password',
            ]);
        }

        // avatar upload
        if($request->hasFile('avatar')){
            $request->validate([
                'avatar' => 'required|image|mimes:jpeg,png,jpg,gif,svg',
            ]);
            if($user->avatar){
                Storage::delete($user->avatar);
            }
            $user->avatar = $request->avatar->store('avatars');
        }

        $user->name = $request->name;
        $user->email = $request->email;
        $user->username = $request->username;
        $user->whatsapp = $request->whatsapp;
        $user->saldo = floatval($request->saldo);
        $user->role = $request->role;
        $user->about = $request->about;
        $user->suspended = $request->suspended ?? null;
        if($request->new_password){
            $user->password = bcrypt($request->new_password);
        }
        $user->save();

        return response()->json([
            'status' => 'success',
            'message' => 'User updated successfully.'
        ]);
    }

    public function changePlan(Request $request, $id){
        $user = User::find($id);
        if(!$user) return redirect()->route('admin.users.index')->with('error','User not found.');
        $client = new Client();
        if($request->isMethod('POST') && $request->ajax()){
            try{
                $request->validate([
                    'plan_new' => 'required'
                ]);
                $client->post(rtrim(config('app.api_velixs_endpoint'), '/').'/velixs/apikey/plan/'.$id,[
                    'headers' => [
                        'Content-Type' => 'application/json',
                        'X-Secret-Key' => config('app.api_velixs_secret'),
                        'X-Wow' => config('app.api_velixs_wow')
                    ],
                    'body' => json_encode(array(
                        'plan_id' => $request->plan_new,
                        'expired_at' => $request->expired_new==0 ? null : $request->expired_new
                    ))
                ]);
                return response()->json([
                    'status' => 'success',
                    'message' => 'Plan updated successfully.',
                ]);
            }catch(\Exception $e){
                return response()->json([
                    'status' => 'error',
                    'message' => $e->getMessage()
                ], 500);
            }
        }else{
            $response = $client->get(rtrim(config('app.api_velixs_endpoint'), '/').'/velixs/apikey/userid/'.$id,[
                'headers' => [
                    'Content-Type' => 'application/json',
                    'X-Secret-Key' => config('app.api_velixs_secret'),
                    'X-Wow' => config('app.api_velixs_wow')
                ]
            ]);
            $api_plan = json_decode($response->getBody()->getContents(), true);
            $api = $api_plan['data'];
            $expired = Carbon::now()->diffInDays(Carbon::parse($api_plan['data']['expired_at'] ?? date('Y-m-d H:i:s')));
            $plans = $client->get(rtrim(config('app.api_velixs_endpoint'), '/').'/velixs/plan/dbs/',[
                'headers' => [
                    'Content-Type' => 'application/json',
                    'X-Secret-Key' => config('app.api_velixs_secret'),
                    'X-Wow' => config('app.api_velixs_wow')
                ]
            ]);

            $plans = json_decode($plans->getBody()->getContents(), true)['data'];

            return Layouts::view('admin.users.plan',[
                'user' => $user,
                'current' => (object)[
                    'plan' => $api['spec']['plan']['name'] ?? 'FREE',
                    'max_request' => $api['spec']['plan']['max_request'] ?? '-',
                    'current_request' => $api['spec']['current_request'] ?? '-',
                    'expired' => $api['expired_at'] ? $expired.' Days' : '-'
                ],
                'plans' => $plans
            ]);
        }
    }
}
