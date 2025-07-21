<?php

namespace App\Http\Controllers\Admin;

use App\Helpers\Layouts;
use App\Http\Controllers\Controller;
use App\Models\Blog;
use App\Models\BlogTags;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class ABlogController extends Controller
{
    public function index(){
        return Layouts::view('admin.blog.index',[
            'type' => 'all'
        ]);
    }

    public function trash(){
        return Layouts::view('admin.blog.trash',[
            'type' => 'onlytrashed'
        ]);
    }

    public function json(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.blog.index');
        if($request->type == 'onlytrashed'){
            $table = Blog::onlyTrashed()->get();
        } else {
            $table = Blog::all();
        }
        return datatables()->of($table)
            ->editColumn('title', function($row){
                return '<div class="d-flex justify-content-start align-items-center user-name"><div class="avatar-wrapper"><div class="avatar me-2" style="width: 3rem;"><img src="'.$row->_image().'" alt class="rounded" style="object-fit: cover;object-position: center;"></div></div><div class="d-flex flex-column"><span class="emp_name text-truncate">'.$row->title.'</span><small class="emp_post text-truncate text-muted">author : '.$row->_author->username.'</small></div></div>';
            })
            ->editColumn('is_published', function($row){
                switch($row->is_published){
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
            ->addColumn('deleted_at', function($row){
                return $row->deleted_at ? $row->deleted_at->format('M d, Y') : '';
            })
            ->addColumn('updated_at', function($row){
                return $row->updated_at->diffForHumans();
            })
            ->addColumn('created_at', function($row){
                return $row->created_at->format('M d, Y');
            })
            ->addColumn('view', function($row){
                return $row->_countViewShort();
            })
            ->rawColumns(['title', 'is_published', 'price', 'action'])
            ->make(true);
    }

    public function trash_recovery(Request $request,$id){
        if(!$request->ajax()) return redirect()->route('admin.blog.index');
        Blog::onlyTrashed()->where('id', $id)->restore();
        return response()->json([
            'status' => 'success',
            'message' => 'Blog restored successfully'
        ]);
    }

    public function destroy(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.blog.index');
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;
        Blog::whereIn('id', $ids)->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'Blog deleted successfully'
        ]);
    }

    public function destroy_force(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.blog.index');
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;

        $table = Blog::onlyTrashed()->whereIn('id', $ids);
        foreach($table->get() as $p){
            if($p->image) Storage::delete($p->image);
        }
        $table->forceDelete();

        return response()->json([
            'status' => 'success',
            'message' => 'Blog deleted permanently'
        ]);
    }

    public function create(){
        $tags = [];
        foreach(BlogTags::all() as $tag){
            $tags[] = $tag->title;
        }
        $tags = json_encode($tags);
        return Layouts::view('admin.blog.create',[
            'tags' => $tags
        ]);
    }

    public function store(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.blog.index');
        $request->validate([
            'title' => 'required|string|max:255',
            'slug' => 'required|string|max:255|unique:blogs',
            'image' => 'required|image|mimes:jpeg,png,jpg,gif,svg|max:2048',
            'tags' => 'required',
            'is_published' => 'required',
            'content' => 'required',
        ]);

        $table = new Blog();
        $table->title = $request->title;
        $table->slug = $request->slug;
        $table->content = $request->content;
        // image
        $image = $request->file('image')->store('blogs');
        $table->image = $image;
        // tags
        $tags = [];
        foreach(json_decode($request->tags) as $tag){
            $btag = BlogTags::firstOrCreate(['title' => $tag->value],[
                'title' => $tag->value,
                'slug' => trim(strtolower(str_replace(' ', '-', $tag->value))),
            ])->id;
            $tags[] = $btag;
        }
        $table->tags = $tags;
        $table->is_published = $request->is_published;
        $table->author = auth()->id();
        $table->meta_description = substr(strip_tags($request->content), 0, 160);
        $table->save();

        return response()->json([
            'status' => 'success',
            'message' => 'Blog created successfully',
            'redirect_edit' => route('admin.blog.edit', $table->id)
        ]);
    }

    public function edit($id){
        $table = Blog::find($id);
        if(!$table) return redirect()->route('admin.blog.index')->with('info', 'Blog not found.');
        // show tags
        $tags = [];
        foreach(BlogTags::all() as $tag){
            $tags[] = $tag->title;
        }

        return Layouts::view('admin.blog.edit',[
            'row' => $table,
            'tags' => json_encode($tags)
        ]);
    }

    public function update(Request $request, $id){
        if(!$request->ajax()) return redirect()->route('admin.blog.index');

        $table = Blog::find($id);
        if(!$table) return response()->json([
            'message' => 'Blog not found.'
        ], 404);

        $request->validate([
            'title' => 'required|string|max:255',
            'slug' => 'required|string|max:255|unique:blogs,slug,'.$table->id,
            'image' => 'nullable|image|mimes:jpeg,png,jpg,gif,svg|max:2048',
            'tags' => 'required',
            'is_published' => 'required',
            'meta_description' => 'nullable|string|max:160',
            'content' => 'required',
        ]);

        $table->title = $request->title;
        $table->slug = $request->slug;
        $table->content = $request->content;
        // image
        if($request->hasFile('image')){
            if($table->image) Storage::delete($table->image);
            $image = $request->file('image')->store('blogs');
            $table->image = $image;
        }
        // tags
        $tags = [];
        foreach(json_decode($request->tags) as $tag){
            $btag = BlogTags::firstOrCreate(['title' => $tag->value],[
                'title' => $tag->value,
                'slug' => trim(strtolower(str_replace(' ', '-', $tag->value))),
            ])->id;
            $tags[] = $btag;
        }
        $table->tags = $tags;
        $table->is_published = $request->is_published;
        $table->meta_description = $request->meta_description;
        $table->save();

        return response()->json([
            'status' => 'success',
            'message' => 'Blog updated successfully',
        ]);
    }


    public function tags_index(Request $request){
        if($request->ajax()){
            $tags = BlogTags::all();
            return datatables()->of($tags)
                // ->rawColumns(['action'])
                ->make(true);
        } else {
            return Layouts::view('admin.blog.tags');
        }
    }

    public function tags_create(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.blog.tags');
        $request->validate([
            'title' => 'required|string|max:255|unique:blog_tags',
            'slug' => 'required|string|max:255|unique:blog_tags',
        ]);

        $tag = new BlogTags();
        $tag->title = $request->title;
        $tag->slug = $request->slug;
        $tag->save();

        return response()->json([
            'status' => 'success',
            'message' => 'Blog tags created successfully'
        ]);
    }

    public function tags_destroy(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.blog.tags');
        $request->validate([
            'ids' => 'required|array',
        ]);
        $ids = $request->ids;
        BlogTags::whereIn('id', $ids)->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'Blog tags deleted successfully'
        ]);
    }

    public function tags_edit(Request $request,$id){
        if(!$request->ajax()) return redirect()->route('admin.blog.tags');
        $tag = BlogTags::find($id);
        if(!$tag) return response()->json([
            'message' => 'Blog tags not found.'
        ], 404);
        return response()->json([
            'status' => 'success',
            'data' => $tag
        ]);
    }

    public function tags_update(Request $request){
        if(!$request->ajax()) return redirect()->route('admin.blog.tags');
        $tag = BlogTags::find($request->id);
        if(!$tag) return response()->json([
            'message' => 'Blog tags not found.'
        ], 404);

        $request->validate([
            'title' => 'required|string|max:255|unique:blog_tags,title,'.$tag->id,
            'slug' => 'required|string|max:255|unique:blog_tags,slug,'.$tag->id,
        ]);

        $tag->title = $request->title;
        $tag->slug = $request->slug;
        $tag->save();

        return response()->json([
            'status' => 'success',
            'message' => 'Blog tags updated successfully'
        ]);
    }
}
