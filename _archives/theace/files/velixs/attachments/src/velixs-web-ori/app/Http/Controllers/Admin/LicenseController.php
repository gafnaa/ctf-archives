<?php

namespace App\Http\Controllers\Admin;

use App\Helpers\Layouts;
use App\Http\Controllers\Controller;
use App\Models\License;
use App\Models\OwnedLicense;
use App\Models\Product;
use Illuminate\Http\Request;

class LicenseController extends Controller
{
    public function index(){
        return Layouts::view('admin.license.index',[
            'products' => Product::paidOnly()->get()
        ]);
    }

    public function json(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.license.index');
        $table = License::all();
        return datatables()->of($table)
            ->editColumn('item_id', function($row){
                return $row->_item ? '<a href="'.route('product.detail',$row->_item->slug).'">'.$row->_item->title.'</a>' : '<span class="badge bg-label-danger">Invalid Product</span>';
            })
            ->editColumn('expires_at', function($row){
                return $row->expires_at ? $row->expires_at : '<span class="badge bg-label-info">-</span>';
            })
            ->rawColumns(['item_id','expires_at'])
            ->make(true);
    }

    public function generate_license_key(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.license.index');
        $request->validate([
            'type' => 'required',
        ]);

        return Layouts::MakeLicense($request->type);
    }

    public function create(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.license.index');
        $request->validate([
            'item' => 'required',
            'item_id' => 'required',
            'license_key' => 'required|unique:licenses',
            'expires_at' => 'nullable|date',
        ]);

        $license = new License();
        $license->item = $request->item;
        $license->item_id = $request->item_id;
        $license->license_key = $request->license_key;
        $license->expires_at = $request->expires_at;
        $license->save();

        return response()->json([
            'status' => 'success',
            'message' => 'License created successfully'
        ]);
    }

    public function destroy(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.license.index');
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;
        License::whereIn('id', $ids)->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'License deleted successfully'
        ]);
    }

    public function purchases(Request $request){
        return Layouts::view('admin.license.purchases');

    }

    public function purchases_json(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.purchases.index');
        $table = OwnedLicense::select('*');
        if($request->get('user')){
            $table->whereHas('_user',function($q) use ($request){
                $q->where('username',$request->get('user'));
            });
        }
        return datatables()->of($table->get())
            ->editColumn('item_id', function($row){
                return $row->_item ? '<a href="'.route('product.detail',$row->_item->slug).'">'.$row->_item->title.'</a>' : '<span class="badge bg-label-danger">Invalid Product</span>';
            })
            ->editColumn('expires_at', function($row){
                return $row->expires_at ? $row->expires_at : '<span class="badge bg-label-info">-</span>';
            })
            ->editColumn('user', function($row){
                return $row->_user->name;
            })
            ->addColumn('created_at',function($row){
                return $row->created_at->diffForHumans();
            })
            ->rawColumns(['item_id','expires_at'])
            ->make(true);
    }

    public function purchases_destroy(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.license.purchases');
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;
        OwnedLicense::whereIn('id', $ids)->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'License deleted successfully'
        ]);
    }
}
