<?php

namespace App\Http\Controllers\Admin;

use App\Helpers\Layouts;
use App\Http\Controllers\Controller;
use App\Models\Product;
use App\Models\User;
use App\Models\UserTransaction;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class RefController extends Controller
{
    public function index(Request $request){
        $type = $request->type ?? 'earnings';
        $user = $request->user;
        $display_title = $type == 'earnings' ? 'Earnings' : 'Referrals';
        if($request->ajax()){
            $table = UserTransaction::select("*");
            $table->where('type',$type);
            if($user) {
                $table->whereHas('_user', function ($query) use ($user) {
                    $query->where('username', $user);
                });
            }
            $table->orderBy('created_at', 'desc');
            return datatables()->of($table->get())
            ->editColumn('desc', function($row){
                if (preg_match_all('/<@(user|item):([^>]+)>/', $row->description, $matches)) {
                    $user_id = $matches[2][0];
                    $item_id = $matches[2][1];
                    $user = User::where('id',$user_id)->first();
                    $item = Product::where('id',$item_id)->first();
                    return $row->description = preg_replace(
                        [
                            '/<@(user):([^>]+)>/',
                            '/<@(item):([^>]+)>/'
                        ],
                        [
                            $user ? '<a href="'.route('profile',$user->username).'">'.$user->username.'</a>' : 'N/A',
                            $item ? '<a href="'.route('product.detail',$item->slug).'">'.$item->title.'</a>' : 'N/A'
                        ],
                        $row->description
                    );
                }
                return $row->description;
            })
            ->editColumn('amount', function($row){
                if($row->type=='withdraw'){
                    return $row->amount = "- ". number_format($row->amount, 2, '.', ',');
                }else if($row->type=='earnings'){
                    return $row->amount = "<span class='text-success'>+</span> ". number_format($row->amount, 2, '.', ',');
                }
            })
            ->addColumn('owner',function($row){
                return '<a href="'.route('profile',$row->_user->username).'">'.$row->_user->username.'</a>';
            })
            ->editColumn('created_at', function($row){
                return $row->created_at->format('d, M Y - h:i A');
            })
            ->editColumn('status', function($row){
                switch($row->status){
                    case 'pending':
                        return '<a href="javascript:void(0)" data-id="'.$row->id.'" data-bs-toggle="modal" data-bs-target="#modalstatus" class="badge btn-edit-status bg-label-warning">Pending</a>';
                        break;
                    case 'approved':
                        return '<a href="javascript:void(0)" data-id="'.$row->id.'" data-bs-toggle="modal" data-bs-target="#modalstatus" class="badge btn-edit-status bg-label-success">Approved</a>';
                        break;
                    case 'rejected':
                        return '<span class="badge btn-edit-status bg-label-secondary">Rejected</span>';
                        break;
                    default:
                        return '<span class="badge btn-edit-status bg-label-secondary">-</span>';
                        break;
                }
            })
            ->rawColumns(['desc', 'amount', 'owner', 'status'])
            ->make(true);

        } else {
            if($type=='earnings'){
                return Layouts::view('admin.ref.index', [
                    'display_title' => $display_title,
                    'type' => $type,
                    'user' => $user
                ]);
            }else{
                return Layouts::view('admin.ref.withdraw', [
                    'display_title' => $display_title,
                    'type' => $type,
                    'user' => $user
                ]);
            }
        }
    }

    public function destroy(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.ref.index');
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;
        UserTransaction::whereIn('id', $ids)->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'Referral deleted successfully'
        ]);
    }

    public function edit_status_ajax(Request $request, $id){
        if(!$request->ajax()) return redirect()->route('admin.ref.index');
        $table = UserTransaction::where('id', $id)->first();
        return response()->json([
            'status' => 'success',
            'message' => 'get data successfully',
            'data' => $table
        ]);
    }

    public function update_status_ajax(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.ref.index');
        $table = UserTransaction::where('id', $request->id)->first();
        if(!$table) return response()->json([
            'status' => 'error',
            'message' => 'Data not found'
        ], 404);
        try{
            DB::beginTransaction();
            if($request->status=='rejected'){
                $user = User::where('id', $table->user_id)->first();
                $user->saldo += floatval($table->amount);
                $user->save();
            }
            $table->status = $request->status;
            $table->message_status = $request->message_status;
            $table->save();
            DB::commit();
        }catch(\Exception $e){
            DB::rollBack();
            return response()->json([
                'status' => 'error',
                'message' => $e->getMessage()
            ], 500);
        }
        return response()->json([
            'status' => 'success',
            'message' => 'Status updated successfully'
        ]);
    }
}
