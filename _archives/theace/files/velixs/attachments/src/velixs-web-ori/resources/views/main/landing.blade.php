@extends('layouts.landing.main')

@section('content')
    <div class="relative isolate overflow-hidden bg-white dark:bg-slate-950">
        <svg viewBox="0 0 1108 632" aria-hidden="true" class="absolute top-10 left-[calc(50%-4rem)] -z-10 w-[69.25rem] max-w-none transform-gpu blur-3xl sm:left-[calc(50%-18rem)] lg:left-48 lg:top-[calc(50%-30rem)] xl:left-[calc(50%-24rem)]">
            <path fill="url(#175c433f-44f6-4d59-93f0-c5c51ad5566d)" fill-opacity=".2" d="M235.233 402.609 57.541 321.573.83 631.05l234.404-228.441 320.018 145.945c-65.036-115.261-134.286-322.756 109.01-230.655C968.382 433.026 1031 651.247 1092.23 459.36c48.98-153.51-34.51-321.107-82.37-385.717L810.952 324.222 648.261.088 235.233 402.609Z" />
            <defs>
                <linearGradient id="175c433f-44f6-4d59-93f0-c5c51ad5566d" x1="1220.59" x2="-85.053" y1="432.766" y2="638.714" gradientUnits="userSpaceOnUse">
                    <stop stop-color="#4F46E5"></stop>
                    <stop offset="1" stop-color="#80CAFF"></stop>
                </linearGradient>
            </defs>
        </svg>
        <div class="mx-auto max-w-7xl px-6 md:flex md:items-center md:gap-x-10 md:px-8 ">
            <div class="mx-auto max-w-2xl md:flex-auto mt-32">
                <div class="animate-fade-in-left-bounce">
                    <a href="{!! route('rapi') !!}" class="inline-flex space-x-6">
                        <span class="rounded-full bg-primary-600/10 px-3 py-1 text-sm font-semibold leading-6 text-primary-600 ring-1 ring-inset ring-primary-600/10">What's new</span>
                        <span class="inline-flex items-center space-x-2 text-sm font-semibold leading-6 text-gray-600 dark:text-gray-300">
                            <span>API Hub</span>
                            <svg class="h-5 w-5 text-gray-400 animate-idleX" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd" />
                            </svg>
                        </span>
                    </a>
                </div>
                <h1 class="mt-10 max-w-lg animate-fade-in-left-bounce text-5xl font-bold tracking-tight text-gray-900 dark:text-gray-50 sm:text-6xl">
                    <span class="bg-white dark:bg-slate-800/40 inline-block -rotate-1 shadow py-1 px-3 rounded-xl"><span class="text-transparent bg-clip-text bg-gradient-to-r from-sky-500 to-violet-600">VELIXS</span></span><span class="text-4xl text-outline"> .com</span>
                </h1>
                <p class="mt-6 leading-8 animate-fade-in-left-bounce-2 text-slate-600 dark:text-slate-400">
                    We offer specialized <span class="text-slate-800 dark:text-slate-300 font-semibold">website development</span> services for web developers. With various categories, we also provide complete <span class="text-slate-800 dark:text-slate-500 font-semibold">resources to develop your web projects</span>.
                </p>
                <div class="mt-10 flex items-center gap-x-6">
                    <a href="{!! route('product') !!}" class="btn-gradient-2 text-white tex-sm font-semibold h-12 px-6 rounded-full w-full flex items-center justify-center sm:w-auto transition-all animate-fade-in-left-bounce-3">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                            <path d="M4 13a8 8 0 0 1 7 7a6 6 0 0 0 3 -5a9 9 0 0 0 6 -8a3 3 0 0 0 -3 -3a9 9 0 0 0 -8 6a6 6 0 0 0 -5 3"></path>
                            <path d="M7 14a6 6 0 0 0 -3 6a6 6 0 0 0 6 -3"></path>
                            <path d="M15 9m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0"></path>
                        </svg> Projects
                    </a>
                    <button type="button" class="btn-search hidden sm:flex w-72 items-center xl:w-72 lg:w-72 mt-3 xl:mt-0 lg:mt-0 text-left space-x-3 px-4 h-12 bg-white ring-1 ring-slate-900/10 hover:ring-slate-300 shadow-sm rounded-full text-slate-400 dark:bg-slate-800 dark:ring-0 dark:text-slate-300 dark:highlight-white/5 dark:hover:bg-slate-700 transition-all animate-fade-in-left-bounce-4">
                        <svg width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="flex-none text-slate-300 dark:text-slate-400" aria-hidden="true">
                            <path d="m19 19-3.5-3.5"></path>
                            <circle cx="11" cy="11" r="6"></circle>
                        </svg>
                        <span class="flex-auto font-sans font-semibold text-sm" data-btn-search="">Quick search...</span>
                        <kbd class="font-sans font-semibold dark:text-slate-500 text-xs">
                            CTRL + F
                        </kbd>
                    </button>
                </div>
            </div>

            <div class="md:flex-shrink-0 md:flex-grow animate-fade-in-left-bounce-2">{{-- lg:h-[50rem] sm:h-[45rem] --}}
                <img src="{{ asset('assets/img/ascot1.png') }}" alt="VELIXS">
            </div>
        </div>
        <div class="absolute left-[5rem] bottom-0 flex h-8 items-end overflow-hidden">
            <div class="flex -mb-px h-[2px] w-[29rem] -scale-x-100">
                <div class="w-full flex-none blur-sm [background-image:linear-gradient(90deg,rgba(56,189,248,0)_0%,#0EA5E9_32.29%,rgba(236,72,153,0.3)_67.19%,rgba(236,72,153,0)_100%)]"></div>
                <div class="-ml-[100%] w-full flex-none blur-[1px] [background-image:linear-gradient(90deg,rgba(56,189,248,0)_0%,#0EA5E9_32.29%,rgba(236,72,153,0.3)_67.19%,rgba(236,72,153,0)_100%)]"></div>
            </div>
        </div>
    </div>

    <main class="bg-white dark:bg-slate-950">
        <!-- This example requires Tailwind CSS v3.0+ -->
        <div class="mb-5">
            <div class="py-24 px-6 sm:px-6 sm:py-32 lg:px-8">
                <div class="mx-auto max-w-2xl text-center">
                    <h2 class="text-4xl font-bold tracking-tight text-gray-900 dark:text-slate-50">Boost your productivity.<br>Start using our app today.</h2>
                    <p class="mx-auto mt-6 max-w-xl text-lg leading-8 text-gray-600 dark:text-slate-400">We provide various ready-to-use tools to facilitate your business.</p>
                    <div class="mt-4 flex items-center justify-center gap-x-6">
                        <a class="inline-flex items-center gap-x-1 justify-center rounded-full text-sm font-medium btn-gradient-2 px-3 py-1.5 text-slate-50 group relative" href="{!! route('product') !!}"><span class="mr-6">Get started</span> <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="absolute right-0 mr-4 !h-4 shrink-0 !stroke-2 duration-300 group-hover:mr-3"><path d="M5 12l14 0"></path><path d="M13 18l6 -6"></path><path d="M13 6l6 6"></path></svg></a>
                    </div>
                </div>
            </div>
        </div>

        <section id="article" class="relative px-6 lg:px-10 pb-20">
            <div class="relative mx-auto max-w-7xl ">
                <div class="mb-4">
                    <h2 class="text-lg font-semibold leading-6 text-slate-800 dark:text-slate-100">Latest Article</h2>
                    <p class="text-sm text-slate-600 dark:text-slate-300">The latest article that we have published.</p>
                </div>
                <div class="mx-auto grid gap-9 lg:grid-cols-3 md:grid-cols-2">
                    @foreach ($blog_latest as $blogl)
                        <section class="flex flex-col overflow-hidden rounded-xl transform transition-all animate-bounce-in">
                            <div class="flex flex-1 flex-col justify-between">
                                <a href="{!! route('blog.detail',$blogl->slug) !!}" class="aspect-w-4 aspect-h-[2.7] mb-4 overflow-hidden rounded-lg bg-gray-300 dark:bg-gray-700">
                                    <img src="{!! $blogl->_image() !!}" alt="thumb" class="object-cover object-center">
                                </a>
                                <div class="px-2 pb-5">
                                    <div class="flex-1">
                                        <div class="flex items-center gap-x-4 text-xs">
                                            <time class="text-slate-400">{{ $blogl->created_at->format('d M Y') }}</time>
                                            @foreach ($blogl->_tags() as $index => $tag)
                                                @if ($index <= 1)
                                                    <a class="relative rounded-full transition bg-slate-50 py-1.5 px-3 font-medium text-slate-600 hover:bg-slate-100 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700" href="{!! route('blog','tags='.$tag->slug) !!}">{{ $tag->title }}</a>
                                                @else
                                                    <div class="bg-slate-100 dark:text-slate-100 text-slate-800 dark:bg-slate-700 px-2.5 font-medium py-1 text-xs rounded-full">
                                                        ...
                                                    </div>
                                                @endif
                                            @endforeach
                                        </div>
                                        <a href="{!! route('blog.detail',$blogl->slug) !!}" class="mt-2 block">
                                            <p class="font-semibold text-gray-900 dark:text-gray-200 overflow-hidden line-clamp-1">{{ $blogl->title }}</p>
                                            <p class="mt-2 text-sm text-gray-500 dark:text-gray-400 overflow-hidden line-clamp-2">{{ $blogl->meta_description }}</p>
                                        </a>
                                    </div>
                                    <div class="mt-3 flex items-center">
                                        <div class="flex-shrink-0">
                                            <a href="{!! route('profile',$blogl->_author->username) !!}">
                                                <span class="sr-only">Ilsya</span>
                                                <img class="h-7 w-7 rounded-full" src="{!! $blogl->_author->_avatar() !!}" alt="">
                                            </a>
                                        </div>
                                        <div class="ml-3">
                                            <p class="text-sm font-medium text-gray-500 dark:text-gray-400">
                                                <a href="{!! route('profile',$blogl->_author->username) !!}">{{ $blogl->_author->name }}</a>
                                            </p>
                                        </div>
                                    </div>
                                </div>

                            </div>
                        </section>
                    @endforeach
                </div>
                <div class="mt-6 flex lg:justify-end justify-center"><a class="inline-flex items-center gap-x-1 justify-center rounded-full text-sm font-medium btn-gradient-2 px-3 py-1.5 text-slate-50 group relative" href="{!! route('blog') !!}"><span class="mr-6">Show more.</span> <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="absolute right-0 mr-4 !h-4 shrink-0 !stroke-2 duration-300 group-hover:mr-3"><path d="M5 12l14 0"></path><path d="M13 18l6 -6"></path><path d="M13 6l6 6"></path></svg></a></div>
            </div>
        </section>

        <!-- team seection start -->
        <section id="ourteam">
            <div class="">
                <div class="mx-auto max-w-7xl py-12 px-6 text-center lg:px-8 lg:py-24">
                    <div class="space-y-8 sm:space-y-12">
                        <div class="space-y-5 sm:mx-auto sm:max-w-xl sm:space-y-4 lg:max-w-5xl">
                            <h2 class="text-3xl font-bold tracking-tight sm:text-4xl dark:text-slate-100">Our Team</h2>
                            <p class="text-gray-500 dark:text-slate-400">Great team behind the quality content we make.</p>
                        </div>
                        <ul role="list" class="mx-auto grid content-center grid-cols-2 gap-x-4 gap-y-8 sm:grid-cols-2 md:gap-x-6 lg:max-w-5xl lg:gap-x-8 lg:gap-y-12 xl:grid-cols-4 lg:grid-cols-4">
                            <li>
                                <a href="{!! route('profile','ilsya') !!}" class="space-y-4">
                                    <img class="mx-auto h-20 w-20 shadow border dark:border-none rounded-full lg:h-24 lg:w-24" src="{{ asset("assets/img/team/ilsya.webp") }}" alt="">
                                    <div class="space-y-2">
                                        <div class="text-xs font-medium lg:text-sm">
                                            <h3 class="dark:text-slate-200">Ilsya</h3>
                                            <p class="text-indigo-600 dark:text-indigo-400">Founder</p>
                                        </div>
                                    </div>
                                </a>
                            </li>
                            <li>
                                <div class="space-y-4">
                                    <img class="mx-auto h-20 shadow w-20 rounded-full lg:h-24 lg:w-24" src="assets/img/team/nakiri.jpg" alt="">
                                    <div class="space-y-2">
                                        <div class="text-xs font-medium lg:text-sm">
                                            <h3 class="dark:text-slate-200">Nakiri AI</h3>
                                            <p class="text-indigo-600 dark:text-indigo-400">Chief Marketing Officer</p>
                                        </div>
                                    </div>
                                </div>
                            </li>
                            <li>
                                <div class="space-y-4">
                                    <img class="mx-auto h-20 w-20 shadow border dark:border-none rounded-full lg:h-24 lg:w-24" src="assets/img/team/chatgbt1.jpg" alt="">
                                    <div class="space-y-2">
                                        <div class="text-xs font-medium lg:text-sm">
                                            <h3 class="dark:text-slate-200">ChatGPT</h3>
                                            <p class="text-indigo-600 dark:text-indigo-400">Chief Technology Officer</p>
                                        </div>
                                    </div>
                                </div>
                            </li>
                            <li>
                                <div class="space-y-4">
                                    <img class="mx-auto h-20 w-20 shadow border dark:border-none rounded-full lg:h-24 lg:w-24" src="assets/img/team/chatgbt2.jpg" alt="">
                                    <div class="space-y-2">
                                        <div class="text-xs font-medium lg:text-sm">
                                            <h3 class="dark:text-slate-200">ChatGPT</h3>
                                            <p class="text-indigo-600 dark:text-indigo-400">Chief Creative Officer</p>
                                        </div>
                                    </div>
                                </div>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </section>
        <!-- team seection end -->
    </main>
    @include('layouts.landing.footer')
@endsection
