<?php

namespace App\Http\Controllers\Admin;

use App\Helpers\Layouts;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class FilesController extends Controller
{
    public function index(){
        return Layouts::view('admin.files.index');
    }

    public function fortinymce(Request $request){
        if($request->type=='shadow'){
            return view('admin.files.shadow');
        }else{
            return view('admin.files.tinymce5');
        }
    }
}
