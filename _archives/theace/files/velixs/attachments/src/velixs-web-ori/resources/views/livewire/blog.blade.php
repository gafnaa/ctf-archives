<div>


    <main class="lg:mt-0 md:mt-10 mt-20">
        <div class="relative isolate overflow-hidden md:block hidden">
            <div class="absolute inset-x-0 midnight:hidden -top-40 -z-10 transform-gpu overflow-hidden blur-3xl sm:-top-80" aria-hidden="true">
                <div class="relative left-[calc(50%-11rem)] aspect-[1155/678] w-[36.125rem] -translate-x-1/2 rotate-[30deg] bg-gradient-to-tr from-sky-800/90 to-blue-800/90 opacity-20 sm:left-[calc(50%-30rem)] sm:w-[72.1875rem]" style="clip-path: polygon(74.1% 44.1%, 100% 61.6%, 97.5% 26.9%, 85.5% 0.1%, 80.7% 2%, 72.5% 32.5%, 60.2% 62.4%, 52.4% 68.1%, 47.5% 58.3%, 45.2% 34.5%, 27.5% 76.7%, 0.1% 64.9%, 17.9% 100%, 27.6% 76.8%, 76.1% 97.7%, 74.1% 44.1%);"></div>
            </div>
            <svg viewBox="0 0 1108 632" aria-hidden="true" class="absolute top-10 left-[calc(50%-4rem)] -z-10 w-[69.25rem] max-w-none transform-gpu blur-3xl sm:left-[calc(50%-18rem)] lg:left-48 lg:top-[calc(50%-30rem)] xl:left-[calc(50%-24rem)]">
                <path fill="url(#175c433f-44f6-4d59-93f0-c5c51ad5566d)" fill-opacity=".2" d="M235.233 402.609 57.541 321.573.83 631.05l234.404-228.441 320.018 145.945c-65.036-115.261-134.286-322.756 109.01-230.655C968.382 433.026 1031 651.247 1092.23 459.36c48.98-153.51-34.51-321.107-82.37-385.717L810.952 324.222 648.261.088 235.233 402.609Z" />
                <defs>
                    <linearGradient id="175c433f-44f6-4d59-93f0-c5c51ad5566d" x1="1220.59" x2="-85.053" y1="432.766" y2="638.714" gradientUnits="userSpaceOnUse">
                        <stop stop-color="#4F46E5"></stop>
                        <stop offset="1" stop-color="#80CAFF"></stop>
                    </linearGradient>
                </defs>
            </svg>
            <div class="pt-16 sm:pt-16 md:pt-16 md:pb-0 max-w-screen-2xl mx-auto overflow-hidden lg:grid lg:grid-cols-12 lg:items-center lg:pt-40 lg:pb-28">
                @foreach ($blogs as $blog)
                    <div class="col-span-6 sm:px-6 lg:pl-0 max-w-2xl px-4 col-start-2 lg:px-0 ml-0 lg:ml-[-1rem] xl:ml-[-0.5rem] lg:flex-auto lg:pr-16">
                        <div class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs tracking-tight font-medium transition-colors focus:outline-none border-pink-500/40 bg-pink-500/10 text-pink-500 hover:bg-pink-500/20 mb-4">VelixS Latest Article</div>
                        <h1 class="lg:max-w-lg text-2xl font-bold tracking-tighter dark:text-white sm:text-3xl lg:text-4xl/[2.5rem]">{{ $blog->title }}</h1>
                        <p class="mt-2 lg:max-w-xl leading-relaxed dark:text-slate-400 text-slate-600 sm:mt-4 sm:text-lg sm:leading-7">{{ $blog->meta_description }}</p>
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-x-1 mt-4">
                                @foreach ($blog->_tags() as $tag)
                                <button type="button" wire:click='setTags("{{$tag->slug}}")'  class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs tracking-tight font-medium transition-colors focus:outline-none border-cyan-500/40 bg-cyan-500/10 text-cyan-500 hover:bg-cyan-500/20">{{ $tag->title }}</button>
                                @endforeach
                            </div>
                        </div>
                        <div class="mt-6 flex items-center gap-x-6 lg:mt-10">
                            <a
                                class="inline-flex gap-x-1 items-center justify-center text-sm font-medium bg-slate-900 dark:bg-white dark:text-slate-900 text-white h-10 px-4 py-2 rounded-full"
                                href="{!! route('blog.detail',$blog->slug) !!}"
                                >
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M4 13a8 8 0 0 1 7 7a6 6 0 0 0 3 -5a9 9 0 0 0 6 -8a3 3 0 0 0 -3 -3a9 9 0 0 0 -8 6a6 6 0 0 0 -5 3"></path>
                                    <path d="M7 14a6 6 0 0 0 -3 6a6 6 0 0 0 6 -3"></path>
                                    <path d="M15 9m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0"></path>
                                </svg>
                                Baca selengkapnya
                            </a>
                        </div>
                        <div class="my-8 flex items-center justify-between gap-x-2">
                            <div class="tracking-tighter text-sm dark:text-slate-300 text-slate-600"><span>Diterbitkan pada {{ $blog->created_at->format('d M Y') }} oleh<a class="hover:text-foreground" href=" {{ route("profile",$blog->_author->username) }}">  {{ $blog->_author->name }}</a></span></div>
                            <div class="hidden lg:flex items-center justify-end gap-x-1"></div>
                        </div>
                    </div>
                    <div class="mt-6 sm:mt-8 lg:mr-4 lg:-mt-10 col-span-5 lg:flex-shrink-0 lg:flex-grow lg:block hidden">
                        <div class="w-full relative">
                            <a href="{!! route('blog.detail',$blog->slug) !!}" class="max-w-3xl sm:max-w-5xl lg:max-w-none">
                                <div wire:loading.remove class="max-w-full min-w-full lg:w-[35rem] aspect-w-4 aspect-h-[2.7] mb-4 overflow-hidden rounded-lg bg-gray-300 dark:bg-gray-700 animate-popup-in" >
                                    <img class="w-full object-cover object-center" src="{!! asset($blog->_image()) !!}" alt="{{ $blog->title }}">
                                </div>
                                <div class="max-w-full min-w-full lg:w-[35rem] aspect-w-4 aspect-h-[2.7] mb-4 overflow-hidden rounded-lg bg-gray-300 dark:bg-gray-700 animate-pulse" wire:loading></div>
                            </a>
                        </div>
                    </div>
                    @break
                @endforeach
            </div>
        </div>

        <div class="flex-col p-2 block px-6 pb-0 md:hidden">
            <h3 class="text-xl font-semibold leading-6 tracking-tighter dark:text-white">Articles</h3>
            <p class="mt-1.5 text-sm text-slate-700 dark:text-slate-400">We provide some interesting aticles that you may find useful. Read on to fill your free time.</p>
        </div>

        <div class="relative px-6 pb-20 lg:px-10 lg:pb-28">
            <div class="relative mx-auto max-w-7xl">
                <div class="mx-auto mt-12 grid gap-5 lg:grid-cols-3 md:grid-cols-2">
                    @foreach ($blogs as $index => $blog)
                        {{-- lazy load --}}
                        <section class="flex flex-col overflow-hidden rounded-xl transform transition-all animate-pulse" wire:loading>
                            <div class="flex flex-col justify-between">
                                <div class="aspect-w-4 aspect-h-[2.7] mb-4 overflow-hidden rounded-lg bg-gray-300 dark:bg-gray-700"></div>
                                <div class="px-2 pb-5">
                                    <div class="flex-1">
                                        <div class="mt-4 block">
                                            <p class="h-2 w-[80%] bg-gray-400 dark:bg-gray-800 rounded"></p>
                                            <p class="h-2 mt-5 bg-gray-300 dark:bg-gray-700 rounded"></p>
                                            <p class="h-2 mt-3 bg-gray-300 dark:bg-gray-700 rounded"></p>
                                        </div>
                                    </div>
                                    <div class="mt-3 flex items-center">
                                        <div class="flex-shrink-0">
                                            <a href="#">
                                                <span class="sr-only">Ilsya</span>
                                                <div class="rounded-full bg-gray-300 dark:bg-gray-700 h-7 w-7"></div>
                                            </a>
                                        </div>
                                        <div class="ml-3">
                                            <div class="h-2 w-20 bg-gray-300 dark:bg-gray-700 rounded"></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </section>
                        {{-- lazy load --}}
                        <section class="flex flex-col overflow-hidden rounded-xl transform transition-all animate-popup-in" wire:loading.remove>
                            <div class="flex flex-1 flex-col justify-between">
                                <a href="{!! route('blog.detail', $blog->slug) !!}" class="aspect-w-4 aspect-h-[2.7] mb-4 overflow-hidden rounded-lg bg-gray-300 dark:bg-gray-700">
                                    <img src="{!! asset($blog->_image()) !!}" alt="{{ $blog->title }}" class="object-cover object-center hover:scale-105 w-full h-full transition-transform duration-300">
                                </a>
                                <div class="px-2 pb-5">
                                    <div class="flex-1">
                                        <div class="flex items-center gap-x-2 text-xs">
                                            <time class="text-slate-400">{{ $blog->created_at->diffForHumans() }}</time>
                                            @foreach ($blog->_tags() as $index => $tag)
                                                @if ($index <= 1)
                                                    <button type="button" wire:click='setTags("{{$tag->slug}}")' class="click-top bg-slate-100 hover:bg-slate-300 dark:text-slate-100 text-slate-800 dark:bg-slate-700 dark:hover:bg-slate-600 px-2.5 font-medium py-1 text-xs rounded-full">
                                                        {{ $tag->title }}
                                                    </button>
                                                @else
                                                    <div class="bg-slate-100 dark:text-slate-100 text-slate-800 dark:bg-slate-700 px-2.5 font-medium py-1 text-xs rounded-full">
                                                        ...
                                                    </div>
                                                @endif
                                            @endforeach
                                        </div>
                                        <a href="{!! route('blog.detail', $blog->slug) !!}" class="mt-2 block">
                                            <p class="font-semibold text-gray-900 dark:text-gray-200 overflow-hidden line-clamp-1">{{ $blog->title }}</p>
                                            <p class="mt-2 text-sm text-gray-500 dark:text-gray-400 overflow-hidden line-clamp-2">{{ $blog->meta_description }}</p>
                                        </a>
                                    </div>
                                    <div class="mt-3 flex items-center">
                                        <div class="flex-shrink-0">
                                            <a href="{!! route('profile',$blog->_author->username) !!}">
                                                <span class="sr-only">{{ $blog->_author->name }}</span>
                                                <img class="h-7 w-7 rounded-full" src="{{ $blog->_author->_avatar() }}" alt="">
                                            </a>
                                        </div>
                                        <div class="ml-3">
                                            <p class="text-sm font-medium text-gray-500 dark:text-gray-400">
                                                <a href="{!! route('profile',$blog->_author->username) !!}">{{ $blog->_author->name }}</a>
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </section>
                    @endforeach
                </div>

                {!! $blogs->links('layouts.landing.wire-pagination') !!}

            </div>
        </div>
    </main>

    <script>
        document.addEventListener('livewire:load', function () {
            Livewire.on('scrollToTop', function () {
                window.scrollTo({
                    top: 0,
                    behavior: 'smooth'
                });
            });
        });
    </script>
</div>

