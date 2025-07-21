<?php

namespace App\Http\Controllers;

use App\Helpers\Layouts;
use App\Jobs\InsertReactBlogJob;
use App\Jobs\InsertVisitorBlogJob;
use App\Models\Blog;
use App\Models\BlogReact;
use App\Models\BlogView;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

class BlogController extends Controller
{
    use DispatchesJobs;
    public function index(){
        $data['sort'] = request()->segment(3);
        $data['tags'] = request()->query('tags');
        $data['seo'] = (object)[
            'title' => 'Articles / Velixs',
            'description' => 'We provide some interesting aticles that you may find useful. Read on to fill your free time.',
        ];
        return Layouts::view('blog.index',$data);
    }

    public function show(Request $request, $slug) {
        $row = Blog::where('slug', $slug)
            ->where('is_published', '!=', '0')
            ->first();
        if(!$row) return redirect()->route('blog')->with('bug', 'Article not found.');
        $data['row'] = $row;
        // hit visitor
        $user_id = auth()->check() ? auth()->id() : null;
        $ip = $request->ip();
        $visitor = null;
        if($user_id) {
            $visitor = BlogView::where('blog_id',$row->id)->where('user_id', $user_id);
        } else {
            $visitor = BlogView::where('blog_id',$row->id)->where('ip_address', $ip);
        }

        if(!$visitor->exists()){
            $this->dispatch(new InsertVisitorBlogJob([
                'ip_address' => $ip,
                'user_id' => $user_id,
                'blog_id' => $row->id,
            ]));
        }

        // group by react clap, wow, hmm
        $react_count = BlogReact::selectRaw('react, count(*) as total')
            ->where('blog_id', $row->id)
            ->groupBy('react')
            ->get();

        $data['react_count'] = $react_count->mapWithKeys(function($item){
            return [$item->react => $item->total];
        });

        $data['seo'] = (object)[
            'title' => $row->title,
            'description' => $row->meta_description,
            'image' => $row->_image(),
            'type' => 'Article',
        ];
        return Layouts::view('blog.show',$data);
    }

    public function react(Request $request){
        if(!$request->ajax()) return abort(404);
        $request->validate([
            'blog_id' => 'required',
            'react' => 'required'
        ]);

        $blog_id = $request->blog_id;
        $react = $request->react;
        $authorip = auth()->check() ? auth()->id() : $request->ip();

        if(RateLimiter::tooManyAttempts('react-blog-'.$blog_id.'-'.$authorip, 5)){
            return response()->json([
                'type' => 'limit',
                'message' => 'You have reached the maximum limit of reactions for this article.'
            ], 500);
        }

        if(auth()->check()){
            $react = BlogReact::where('blog_id',$blog_id)->where('user_id', auth()->id());
        } else {
            $react = BlogReact::where('blog_id',$blog_id)->where('ip_address', $request->ip());
        }

        RateLimiter::hit('react-blog-'.$blog_id.'-'.$authorip);

        if($react->count() >= 5) return response()->json([
            'type' => 'limit',
            'message' => 'You have reached the maximum limit of reactions for this article.'
        ], 500);

        try {
            BlogReact::create([
                'blog_id' => $blog_id,
                'user_id' => auth()->check() ? auth()->id() : null,
                'ip_address' => $request->ip(),
                'react' => $request->react
            ]);
            return response()->json([
                'message' => 'Thank you for your reaction.'
            ]);
        } catch (\Exception $e){
            return response()->json([
                'message' => 'Failed to react.'
            ], 500);
        }
    }
}
