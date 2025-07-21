<!-- footer start -->
<footer class="bg-gray-50 dark:bg-slate-950/75 lg:mb-0 mb-5">
    <div class="mx-auto max-w-7xl overflow-hidden py-4 px-6 lg:px-8">
        <div class="mt-4 flex justify-center space-x-10">
            @foreach ($ws->_social_links() as $sl)
                <a href="{!! $sl->url !!}" class="text-gray-400 hover:text-gray-500">
                    <span class="sr-only">{!! $sl->name !!}</span>
                    {!! $sl->svg !!}
                </a>
            @endforeach
        </div>
        <p class="mt-10 text-center text-xs leading-5 text-gray-500"><span class="font-semibold">{!! $ws->meta_title !!} - WEB</span></p>
        <p class="mt-1 text-center text-xs leading-5 text-gray-500"><span class="font-semibold">&copy; 2023 Ilsya.</span> All rights reserved.</p>
    </div>
</footer>
<!-- footer end -->
