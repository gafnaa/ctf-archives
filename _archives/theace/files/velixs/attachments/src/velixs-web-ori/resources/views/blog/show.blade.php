@extends('layouts.landing.main')

@section('content')

<main>
    <div class="relative lg:border-t dark:border-slate-900 isolate overflow-hidden bg-white dark:bg-slate-950 lg:mt-0 mt-10 hidden">
        <svg class="inline dark:hidden absolute inset-0 -z-10 h-full w-full stroke-slate-200 [mask-image:radial-gradient(100%_100%_at_top_right,white,transparent)]" aria-hidden="true">
            <defs>
                <pattern id="0787a7c5-978c-4f66-83c7-11c213f99cb7" width="200" height="200" x="50%" y="-1" patternUnits="userSpaceOnUse">
                    <path d="M.5 200V.5H200" fill="none"></path>
                </pattern>
            </defs>
            <rect width="100%" height="100%" stroke-width="0" fill="url(#0787a7c5-978c-4f66-83c7-11c213f99cb7)"></rect>
        </svg>
        <svg class="dark:inline hidden absolute inset-0 -z-10 h-full w-full stroke-white/10 [mask-image:radial-gradient(100%_100%_at_top_right,white,transparent)]" aria-hidden="true">
            <defs>
                <pattern id="983e3e4c-de6d-4c3f-8d64-b9761d1534cc" width="200" height="200" x="50%" y="-1" patternUnits="userSpaceOnUse">
                    <path d="M.5 200V.5H200" fill="none"></path>
                </pattern>
            </defs>
            <svg x="50%" y="-1" class="overflow-visible dark:inline hidden fill-slate-800/20">
                <path d="M-200 0h201v201h-201Z M600 0h201v201h-201Z M-400 600h201v201h-201Z M200 800h201v201h-201Z" stroke-width="0"></path>
            </svg>
            <rect width="100%" height="100%" stroke-width="0" fill="url(#983e3e4c-de6d-4c3f-8d64-b9761d1534cc)"></rect>
        </svg>
        <svg viewBox="0 0 1108 632" aria-hidden="true" class="dark:inline hidden absolute top-10 left-[calc(50%-4rem)] -z-10 w-[69.25rem] max-w-none transform-gpu blur-3xl sm:left-[calc(50%-18rem)] lg:left-48 lg:top-[calc(50%-30rem)] xl:left-[calc(50%-24rem)]">
            <path fill="url(#175c433f-44f6-4d59-93f0-c5c51ad5566d)" fill-opacity=".2" d="M235.233 402.609 57.541 321.573.83 631.05l234.404-228.441 320.018 145.945c-65.036-115.261-134.286-322.756 109.01-230.655C968.382 433.026 1031 651.247 1092.23 459.36c48.98-153.51-34.51-321.107-82.37-385.717L810.952 324.222 648.261.088 235.233 402.609Z"></path>
            <defs>
                <linearGradient id="175c433f-44f6-4d59-93f0-c5c51ad5566d" x1="1220.59" x2="-85.053" y1="432.766" y2="638.714" gradientUnits="userSpaceOnUse">
                    <stop stop-color="#4F46E5"></stop>
                    <stop offset="1" stop-color="#80CAFF"></stop>
                </linearGradient>
            </defs>
        </svg>
        <div class="mx-auto max-w-7xl px-6 pb-10 sm:pb-32 lg:flex lg:py-40 lg:px-8">
            <div class="mx-auto max-w-2xl flex-shrink-0 lg:mx-0 lg:max-w-xl lg:pt-8 pt-16">
                <div class="max-w-full min-w-full lg:w-[35rem] aspect-w-4 aspect-h-[2.7] mb-4 overflow-hidden rounded-lg bg-gray-300 dark:bg-gray-700 animate-popup-in" wire:loading.remove>
                    <img class="w-full object-cover object-center rounded-lg sm:max-w-full h-full lg:h-96 transform transition-all duration-150" src="{!! $row->_image() !!}" alt="{{ $row->title }}">
                </div>
            </div>
            <div class="mx-auto max-w-2xl sm:ml-10 lg:mr-0">
                <h1 class="mt-10 font-bold tracking-tight leading-[1.1] text-slate-900 dark:text-white lg:text-3xl md:text-2xl text-lg transition-all animate-fade-in-left-bounce">{{ $row->title }}</h1>
                <p class="mt-1 lg:mt-6 leading-8 text-slate-600 dark:text-slate-300 transition-all animate-fade-in-left-bounce-2 lg:text-base text-sm">{{ $row->meta_description }}</p>
                <div class="font-mono tracking-tighter text-xs sm:text-sm mt-4">
                    <span class="h-px mt-6 mb-5 w-full hidden md:inline-block bg-gradient-to-r from-slate-300 dark:from-slate-700 via-transparent to-transparent"></span>
                    <div class="text-slate-500 dark:text-slate-400">
                        <div class="flex items-center mb-2">
                            <svg xmlns="http://www.w3.org/2000/svg" class="mr-2" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M4 7a2 2 0 0 1 2 -2h12a2 2 0 0 1 2 2v12a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-12z"></path>
                                <path d="M16 3v4"></path>
                                <path d="M8 3v4"></path>
                                <path d="M4 11h16"></path>
                                <path d="M11 15h1"></path>
                                <path d="M12 15v3"></path>
                            </svg>Published on {{ $row->created_at->format('d M, Y') }}
                        </div>
                        <div class="flex items-center mb-2">
                            <svg xmlns="http://www.w3.org/2000/svg" class="mr-2" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M4 20h4l10.5 -10.5a1.5 1.5 0 0 0 -4 -4l-10.5 10.5v4"></path>
                                <path d="M13.5 6.5l4 4"></path>
                            </svg>Ditulis oleh <a class="ml-1.5 font-semibold" href="{!! route('profile',$row->_author->username) !!}">{{ $row->_author->name }}</a>
                        </div>
                        <div class="flex items-center mb-2">
                            <svg xmlns="http://www.w3.org/2000/svg" class="mr-2" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M7.859 6h-2.834a2.025 2.025 0 0 0 -2.025 2.025v2.834c0 .537 .213 1.052 .593 1.432l6.116 6.116a2.025 2.025 0 0 0 2.864 0l2.834 -2.834a2.025 2.025 0 0 0 0 -2.864l-6.117 -6.116a2.025 2.025 0 0 0 -1.431 -.593z"></path>
                                <path d="M17.573 18.407l2.834 -2.834a2.025 2.025 0 0 0 0 -2.864l-7.117 -7.116"></path>
                                <path d="M6 9h-.01"></path>
                            </svg><span class="mr-1">Fill</span>in
                            <div class="ml-3 flex flex-wrap">
                                @foreach ($row->_tags() as $tag)
                                    <a href="{!! route('blog', ['tags'=> $tag->slug]) !!}" class="badge-fillin mb-1 mr-1" href="">{{$tag->title}}</a>
                                @endforeach
                            </div>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </div>

    <div class="relative isolate overflow-hidden lg:border-b dark:border-slate-900">
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
        <div class="pt-20 sm:pt-16 md:pt-16 md:pb-0 max-w-screen-2xl mx-auto overflow-hidden lg:grid lg:grid-cols-12 lg:items-center lg:pt-40 lg:pb-28">
            <div class="col-span-6 sm:px-6 lg:pl-0 max-w-2xl px-4 col-start-2 lg:px-0 ml-0 lg:ml-[-1rem] xl:ml-[-0.5rem] lg:flex-auto lg:pr-16">
                <div class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs tracking-tight font-medium transition-colors focus:outline-none border-pink-500/40 bg-pink-500/10 text-pink-500 hover:bg-pink-500/20 mb-4">Updated at {{ $row->updated_at->format('d M Y') }}</div>
                <h1 class="lg:max-w-lg text-2xl font-bold tracking-tighter dark:text-white sm:text-3xl lg:text-4xl/[2.5rem]">{{ $row->title }}</h1>
                <p class="mt-2 lg:max-w-xl leading-relaxed dark:text-slate-400 text-slate-600 sm:mt-4 sm:text-base text-sm sm:leading-7">{{ $row->meta_description }}</p>
                <div class="flex items-center justify-between">
                    <div class="flex items-center gap-x-1 mt-4">
                        @foreach ($row->_tags() as $tag)
                            <a href="{!! route('blog', ['tags'=> $tag->slug]) !!}" class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs tracking-tight font-medium transition-colors focus:outline-none border-cyan-500/40 bg-cyan-500/10 text-cyan-500 hover:bg-cyan-500/20">{{ $tag->title }}</a>
                        @endforeach
                    </div>
                </div>
                <div class="my-8 flex items-center justify-between gap-x-2">
                    <div class="tracking-tighter text-sm dark:text-slate-300 text-slate-500">
                        <div class="flex">
                            <div class="mr-4 flex-shrink-0">
                                <div class="LazyLoad is-visible"><img class="rounded-full w-12 h-12" src="{{ $row->_author->_avatar() }}" loading="lazy" style="opacity: 1;"></div>
                            </div>
                            <div>
                                <a href="{{ route("profile",$row->_author->username) }}" target="_blank" rel="noopener noreferrer">
                                    <h4 class="md:text-lg text-base font-semibold text-slate-900 dark:text-slate-100">{{ $row->_author->name }}</h4>
                                </a>
                                <p class="text-xs md:text-sm"><span>Diterbitkan pada</span><span class="mx-1">·</span><span>{{ $row->created_at->format('d M Y') }}</span></p>
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center justify-end gap-x-1">
                        <button  x-data @click="$store.modalshare = true" class="inline-flex items-center justify-center font-medium bg-slate-900 dark:bg-white dark:text-black text-white h-7 px-2.5 text-xs rounded-full" type="button" id="radix-:rf:" aria-haspopup="menu" aria-expanded="false" data-state="closed">
                            <svg xmlns="http://www.w3.org/2000/svg" class="mr-1 h-3 w-3" fill="none" viewBox="0 0 24 24">
                                <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.25" d="M12 3.75V15m0-11.25 4.5 4.5M12 3.75l-4.5 4.5m12.75 4.5v4.5a3 3 0 0 1-3 3H6.75a3 3 0 0 1-3-3v-4.5"></path>
                            </svg>Bagikan
                        </button>
                    </div>
                </div>
            </div>
            <div class="mt-6 sm:mt-8 lg:mr-4 lg:-mt-10 col-span-5 lg:flex-shrink-0 lg:flex-grow">
                <div class="w-full relative">
                    <div class="max-w-3xl sm:max-w-5xl lg:max-w-none">
                        <div class="max-w-full min-w-full lg:w-[35rem] aspect-w-4 aspect-h-[2.7] mb-4 overflow-hidden lg:rounded-lg bg-gray-300 dark:bg-gray-700 animate-popup-in" >
                            <img class="w-full object-cover object-center" src="{!! asset($row->_image()) !!}" alt="{{ $row->title }}">
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="mx-auto px-4 sm:px-6 md:px-4 lg:max-w-6xl xl:max-w-7xl lg:px-8">
        <div class="items-start lg:grid lg:grid-cols-12">
            <div class="sticky top-20 col-span-2 mt-14 hidden items-center justify-end gap-x-2 lg:flex">
                <button class="inline-flex items-center justify-center rounded-full font-medium h-7 px-2.5 text-xs border dark:border-slate-400 dark:text-white">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none" viewBox="0 0 24 24" class="mr-2 w-4 h-4 text-brand">
                        <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.25" d="M19.25 18.852V7.55c0-1.68 0-2.52-.327-3.162a3 3 0 0 0-1.311-1.311c-.642-.327-1.482-.327-3.162-.327h-4.9c-1.68 0-2.52 0-3.162.327a3 3 0 0 0-1.311 1.311C4.75 5.03 4.75 5.87 4.75 7.55v11.302c0 1.288 0 1.933.25 2.216a1 1 0 0 0 .863.333c.375-.043.807-.52 1.673-1.475l3.278-3.618c.411-.453.617-.68.858-.764a1 1 0 0 1 .656 0c.241.084.447.31.858.764l3.278 3.618c.866.955 1.298 1.433 1.673 1.475a1 1 0 0 0 .864-.333c.249-.283.249-.928.249-2.216Z"></path>
                    </svg>Bookmark
                </button>
                <div class="xl:block hidden">
                    <button x-data @click="$store.modalshare = true" class="font-medium bg-slate-900 dark:bg-white dark:text-slate-900 text-white h-7 px-2.5 text-xs flex items-center justify-between gap-x-2 rounded-full" type="button" id="radix-:rj:" aria-haspopup="menu" aria-expanded="false" data-state="closed">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none" viewBox="0 0 24 24" class="h-3 w-3">
                            <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.25" d="M12 3.75V15m0-11.25 4.5 4.5M12 3.75l-4.5 4.5m12.75 4.5v4.5a3 3 0 0 1-3 3H6.75a3 3 0 0 1-3-3v-4.5"></path>
                        </svg>Bagikan
                    </button>
                </div>
            </div>
            <div class="col-span-7 relative pb-12 lg:pt-6 lg:rounded-b-lg lg:px-12">
                <article class="prose max-w-none dark:prose-invert prose-img:rounded-xl prose-pre:p-0 prose-pre:m-0 prose-pre:bg-transparent prose-pre:rounded-none">
                    {!! $row->content !!}
                </article>
                <div class="mt-6 space-y-6">
                    <div class="relative isolate mt-10 overflow-hidden rounded-lg p-6 ring-1 ring-input">
                        <div class="flex w-full justify-between">
                            <div>
                                <h4 class="text-lg font-bold dark:text-white">{{ $row->_author->name }}</h4>
                                <p class="mt-1 text-sm dark:text-slate-300 lg:text-base">{{ $row->_author->about }}</p>
                            </div>
                            <a class="ml-4 flex-shrink-0" href="{{ route("profile",$row->_author->username) }}" target="_blank" rel="noopener noreferrer">
                                <span class="relative flex shrink-0 overflow-hidden rounded-full h-12 w-12">
                                    <img class="h-full w-full" src="{{ $row->_author->_avatar() }}">
                                </span>
                            </a>
                        </div>
                        <div class="relative mt-6 flex flex-col justify-between gap-y-10 sm:flex-row sm:items-center sm:gap-y-0">
                            <div>
                                <h5 class="font-mono text-sm dark:text-slate-50">Follow me on</h5>
                                <div class="flex flex-wrap items-center gap-1 mt-2 justify-start gap-x-2 [&amp;>a]:border [&amp;>a]:bg-accent">
                                    <a target="_blank" href="https://github.com/ilsyaa" class="inline-flex items-center justify-center rounded-full text-sm font-medium border dark:border-slate-700 dark:text-white bg-slate-100 dark:bg-slate-800 h-9 w-9" rel="noopener noreferrer">
                                        <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" class="w-4 h-4">
                                            <g clip-path="url(#clip0_910_44)">
                                                <path fill-rule="evenodd" clip-rule="evenodd"
                                                    d="M24.0199 0C10.7375 0 0 10.8167 0 24.1983C0 34.895 6.87988 43.9495 16.4241 47.1542C17.6174 47.3951 18.0545 46.6335 18.0545 45.9929C18.0545 45.4319 18.0151 43.509 18.0151 41.5055C11.3334 42.948 9.94198 38.6209 9.94198 38.6209C8.86818 35.8164 7.27715 35.0956 7.27715 35.0956C5.09022 33.6132 7.43645 33.6132 7.43645 33.6132C9.86233 33.7735 11.1353 36.0971 11.1353 36.0971C13.2824 39.7827 16.7422 38.7413 18.1341 38.1002C18.3328 36.5377 18.9695 35.456 19.6455 34.8552C14.3163 34.2942 8.70937 32.211 8.70937 22.9161C8.70937 20.2719 9.66321 18.1086 11.1746 16.4261C10.9361 15.8253 10.1008 13.3409 11.4135 10.0157C11.4135 10.0157 13.4417 9.3746 18.0146 12.4996C19.9725 11.9699 21.9916 11.7005 24.0199 11.6982C26.048 11.6982 28.1154 11.979 30.0246 12.4996C34.5981 9.3746 36.6262 10.0157 36.6262 10.0157C37.9389 13.3409 37.1031 15.8253 36.8646 16.4261C38.4158 18.1086 39.3303 20.2719 39.3303 22.9161C39.3303 32.211 33.7234 34.2539 28.3544 34.8552C29.2296 35.6163 29.9848 37.0583 29.9848 39.3421C29.9848 42.5871 29.9454 45.1915 29.9454 45.9924C29.9454 46.6335 30.383 47.3951 31.5758 47.1547C41.12 43.9491 47.9999 34.895 47.9999 24.1983C48.0392 10.8167 37.2624 0 24.0199 0Z"
                                                    fill="currentColor">
                                                </path>
                                            </g>
                                            <defs>
                                                <clipPath>
                                                    <rect width="48" height="48" fill="currentColor"></rect>
                                                </clipPath>
                                            </defs>
                                        </svg>
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="lg:block sticky top-20 mt-10 hidden min-h-screen col-span-3">
                <div class="sticky transition-transform transform z-10">

                    <div class="min-w-0 flex-1">
                        <div class="mx-auto max-w-[360px] px-4 sm:max-w-[420px] sm:px-0">

                            <div class="pointer-events-auto relative flex items-center justify-center rounded-xl border p-4 border-slate-200 dark:border-slate-800">
                                <div class="absolute inset-0 rounded-xl bg-white/70 backdrop-blur lg:dark:bg-slate-900/80 dark:bg-slate-950/50"></div>

                                <!-- emot react -->
                                <div class="flex items-center gap-4">
                                    <div class="flex flex-col items-center gap-2">
                                        <button class="btn-react relative cursor-pointer select-none group">
                                            <div data-react="clap" class="h-10 w-10 group-hover:scale-125 transition-transform duration-200 ease-in-out">
                                                <img alt="Clap" src="{!! asset('assets/img/emojis/clapping-hands-animated.png') !!}" class="pointer-events-none h-full w-full">
                                            </div>
                                        </button>
                                        <div class="relative flex h-6 items-center rounded-full bg-slate-200 py-1 px-2 dark:bg-[#1d263a]">
                                            <span class="flex text-sm font-bold text-slate-600 dark:text-slate-300 h-5 items-center" id="count-clap">{{ $react_count['clap'] ?? 0 }}</span>
                                        </div>
                                    </div>

                                    <div class="flex flex-col items-center gap-2">
                                        <button class="btn-react relative cursor-pointer select-none group">
                                            <div data-react="wow" class="h-10 w-10 group-hover:scale-125 transition-transform duration-200 ease-in-out">
                                                <img alt="Wow" src="{!! asset('assets/img/emojis/astonished-face-animated.png') !!}" class="pointer-events-none h-full w-full">
                                            </div>
                                        </button>
                                        <div class="relative flex h-6 items-center rounded-full bg-slate-200 py-1 px-2 dark:bg-[#1d263a]">
                                            <span class="flex text-sm font-bold text-slate-600 dark:text-slate-300 h-5 items-center" id="count-wow">{{ $react_count['wow'] ?? 0 }}</span>
                                        </div>
                                    </div>

                                    <div class="flex flex-col items-center gap-2">
                                        <button class="btn-react relative cursor-pointer select-none group">
                                            <div data-react="hmm" class="h-10 w-10 group-hover:scale-125 transition-transform duration-200 ease-in-out">
                                                <img alt="Hmm" src="{!! asset('assets/img/emojis/face-with-monocle-animated.png') !!}" class="pointer-events-none h-full w-full">
                                            </div>
                                        </button>
                                        <div class="relative flex h-6 items-center rounded-full bg-slate-200 py-1 px-2 dark:bg-[#1d263a]">
                                            <span class="flex text-sm font-bold text-slate-600 dark:text-slate-300 h-5 items-center" id="count-hmm">{{ $react_count['hmm'] ?? 0 }}</span>
                                        </div>
                                    </div>
                                </div>
                                <!-- emot react -->

                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    </div>


    <div x-data x-show="$store.modalshare" x-transition @click.outside="$store.modalshare = false" role="dialog" class="z-50 bg-white dark:bg-slate-950 flex flex-col border-t dark:border-slate-800 rounded-t-[10px] fixed bottom-0 left-0 right-0" style="pointer-events: auto; display: none">
        <div class="p-6 pt-3 bg-accent/40 rounded-t-[10px] flex-1">
            <div class="mx-auto w-12 h-1.5 flex-shrink-0 rounded-full bg-slate-300 dark:bg-slate-700 mb-8"></div>
            <div class="max-w-md mx-auto mt-3">
                <h2 class="font-semibold text-xl mb-1 dark:text-white">Bagikan</h2>
                <p class="mb-6 dark:text-slate-300 text-slate-800">Bagikan artikel ini kepada teman yang lain.</p>
                <div class="flex overflow-x-auto hide-scrollbar [&amp;>button]:shrink-0 items-center gap-1">
                    <button data-clipboard-text="{!! url()->current() !!}" class="copy-link inline-flex items-center justify-center rounded-full font-medium border dark:border-slate-500 dark:text-white px-2.5 text-xs h-10" type="button">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="mr-2 h-4 w-4">
                            <path d="M7.75 7.75V6.75C7.75 5.09315 9.09315 3.75 10.75 3.75H17.25C18.9069 3.75 20.25 5.09315 20.25 6.75V13.26C20.25 14.9169 18.9069 16.26 17.25 16.26H16.25M3.75 10.75V17.25C3.75 18.9069 5.09315 20.25 6.75 20.25H13.25C14.9069 20.25 16.25 18.9069 16.25 17.25V10.75C16.25 9.09315 14.9069 7.75 13.25 7.75H6.75C5.09315 7.75 3.75 9.09315 3.75 10.75Z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"></path>
                        </svg>Copy Link
                    </button>
                </div>
                <div class="flex hide-scrollbar overflow-x-auto gap-4 mt-6">
                    <a target="_blank" href="https://www.facebook.com/sharer/sharer.php?u={!! url()->current() !!}" aria-label="facebook">
                        <svg viewBox="0 0 64 64" width="64" height="64" class="rounded-full w-10 h-10">
                            <rect width="64" height="64" rx="0" ry="0" fill="#3b5998"></rect>
                            <path d="M34.1,47V33.3h4.6l0.7-5.3h-5.3v-3.4c0-1.5,0.4-2.6,2.6-2.6l2.8,0v-4.8c-0.5-0.1-2.2-0.2-4.1-0.2 c-4.1,0-6.9,2.5-6.9,7V28H24v5.3h4.6V47H34.1z" fill="white"></path>
                        </svg>
                    </a>
                    <a target="_blank" href="https://twitter.com/intent/tweet?via=ilsya&amp;url={!! url()->current() !!}" aria-label="twitter">
                        <div class="w-10 h-10 rounded-full bg-black text-white grid place-content-center">
                            <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" class="w-5 h-5">
                                <path d="M36.6526 3.8078H43.3995L28.6594 20.6548L46 43.5797H32.4225L21.7881 29.6759L9.61989 43.5797H2.86886L18.6349 25.56L2 3.8078H15.9222L25.5348 16.5165L36.6526 3.8078ZM34.2846 39.5414H38.0232L13.8908 7.63406H9.87892L34.2846 39.5414Z" fill="currentColor"></path>
                            </svg>
                        </div>
                    </a>
                    <a target="_blank" href="https://www.linkedin.com/sharing/share-offsite/?url={!! url()->current() !!}" aria-label="linkedin">
                        <svg viewBox="0 0 64 64" width="64" height="64" class="rounded-full w-10 h-10">
                            <rect width="64" height="64" rx="0" ry="0" fill="#007fb1"></rect>
                            <path d="M20.4,44h5.4V26.6h-5.4V44z M23.1,18c-1.7,0-3.1,1.4-3.1,3.1c0,1.7,1.4,3.1,3.1,3.1 c1.7,0,3.1-1.4,3.1-3.1C26.2,19.4,24.8,18,23.1,18z M39.5,26.2c-2.6,0-4.4,1.4-5.1,2.8h-0.1v-2.4h-5.2V44h5.4v-8.6 c0-2.3,0.4-4.5,3.2-4.5c2.8,0,2.8,2.6,2.8,4.6V44H46v-9.5C46,29.8,45,26.2,39.5,26.2z" fill="white"></path>
                        </svg>
                    </a>
                    <a target="_blank" href="whatsapp://send?text={!! url()->current() !!}" aria-label="whatsapp">
                        <svg viewBox="0 0 64 64" width="64" height="64" class="rounded-full w-10 h-10">
                            <rect width="64" height="64" rx="0" ry="0" fill="#25D366"></rect>
                            <path
                                d="m42.32286,33.93287c-0.5178,-0.2589 -3.04726,-1.49644 -3.52105,-1.66732c-0.4712,-0.17346 -0.81554,-0.2589 -1.15987,0.2589c-0.34175,0.51004 -1.33075,1.66474 -1.63108,2.00648c-0.30032,0.33658 -0.60064,0.36247 -1.11327,0.12945c-0.5178,-0.2589 -2.17994,-0.80259 -4.14759,-2.56312c-1.53269,-1.37217 -2.56312,-3.05503 -2.86603,-3.57283c-0.30033,-0.5178 -0.03366,-0.80259 0.22524,-1.06149c0.23301,-0.23301 0.5178,-0.59547 0.7767,-0.90616c0.25372,-0.31068 0.33657,-0.5178 0.51262,-0.85437c0.17088,-0.36246 0.08544,-0.64725 -0.04402,-0.90615c-0.12945,-0.2589 -1.15987,-2.79613 -1.58964,-3.80584c-0.41424,-1.00971 -0.84142,-0.88027 -1.15987,-0.88027c-0.29773,-0.02588 -0.64208,-0.02588 -0.98382,-0.02588c-0.34693,0 -0.90616,0.12945 -1.37736,0.62136c-0.4712,0.5178 -1.80194,1.76053 -1.80194,4.27186c0,2.51134 1.84596,4.945 2.10227,5.30747c0.2589,0.33657 3.63497,5.51458 8.80262,7.74113c1.23237,0.5178 2.1903,0.82848 2.94111,1.08738c1.23237,0.38836 2.35599,0.33657 3.24402,0.20712c0.99159,-0.15534 3.04985,-1.24272 3.47963,-2.45956c0.44013,-1.21683 0.44013,-2.22654 0.31068,-2.45955c-0.12945,-0.23301 -0.46601,-0.36247 -0.98382,-0.59548m-9.40068,12.84407l-0.02589,0c-3.05503,0 -6.08417,-0.82849 -8.72495,-2.38189l-0.62136,-0.37023l-6.47252,1.68286l1.73463,-6.29129l-0.41424,-0.64725c-1.70875,-2.71846 -2.6149,-5.85116 -2.6149,-9.07706c0,-9.39809 7.68934,-17.06155 17.15993,-17.06155c4.58253,0 8.88029,1.78642 12.11655,5.02268c3.23625,3.21036 5.02267,7.50812 5.02267,12.06476c-0.0078,9.3981 -7.69712,17.06155 -17.14699,17.06155m14.58906,-31.58846c-3.93529,-3.80584 -9.1133,-5.95471 -14.62789,-5.95471c-11.36055,0 -20.60848,9.2065 -20.61625,20.52564c0,3.61684 0.94757,7.14565 2.75211,10.26282l-2.92557,10.63564l10.93337,-2.85309c3.0136,1.63108 6.4052,2.4958 9.85634,2.49839l0.01037,0c11.36574,0 20.61884,-9.2091 20.62403,-20.53082c0,-5.48093 -2.14111,-10.64081 -6.03239,-14.51915"
                                fill="white"></path>
                        </svg>
                    </a>
                    <a target="_blank" href="https://t.me/share/url?url={!! url()->current() !!}&text={{ $row->title }}" aria-label="telegram" >
                        <svg viewBox="0 0 64 64" width="64" height="64" class="rounded-full w-10 h-10">
                            <rect width="64" height="64" rx="0" ry="0" fill="#37aee2"></rect>
                            <path
                                d="m45.90873,15.44335c-0.6901,-0.0281 -1.37668,0.14048 -1.96142,0.41265c-0.84989,0.32661 -8.63939,3.33986 -16.5237,6.39174c-3.9685,1.53296 -7.93349,3.06593 -10.98537,4.24067c-3.05012,1.1765 -5.34694,2.05098 -5.4681,2.09312c-0.80775,0.28096 -1.89996,0.63566 -2.82712,1.72788c-0.23354,0.27218 -0.46884,0.62161 -0.58825,1.10275c-0.11941,0.48114 -0.06673,1.09222 0.16682,1.5716c0.46533,0.96052 1.25376,1.35737 2.18443,1.71383c3.09051,0.99037 6.28638,1.93508 8.93263,2.8236c0.97632,3.44171 1.91401,6.89571 2.84116,10.34268c0.30554,0.69185 0.97105,0.94823 1.65764,0.95525l-0.00351,0.03512c0,0 0.53908,0.05268 1.06412,-0.07375c0.52679,-0.12292 1.18879,-0.42846 1.79109,-0.99212c0.662,-0.62161 2.45836,-2.38812 3.47683,-3.38552l7.6736,5.66477l0.06146,0.03512c0,0 0.84989,0.59703 2.09312,0.68132c0.62161,0.04214 1.4399,-0.07726 2.14229,-0.59176c0.70766,-0.51626 1.1765,-1.34683 1.396,-2.29506c0.65673,-2.86224 5.00979,-23.57745 5.75257,-27.00686l-0.02107,0.08077c0.51977,-1.93157 0.32837,-3.70159 -0.87096,-4.74991c-0.60054,-0.52152 -1.2924,-0.7498 -1.98425,-0.77965l0,0.00176zm-0.2072,3.29069c0.04741,0.0439 0.0439,0.0439 0.00351,0.04741c-0.01229,-0.00351 0.14048,0.2072 -0.15804,1.32576l-0.01229,0.04214l-0.00878,0.03863c-0.75858,3.50668 -5.15554,24.40802 -5.74203,26.96472c-0.08077,0.34417 -0.11414,0.31959 -0.09482,0.29852c-0.1756,-0.02634 -0.50045,-0.16506 -0.52679,-0.1756l-13.13468,-9.70175c4.4988,-4.33199 9.09945,-8.25307 13.744,-12.43229c0.8218,-0.41265 0.68483,-1.68573 -0.29852,-1.70681c-1.04305,0.24584 -1.92279,0.99564 -2.8798,1.47502c-5.49971,3.2626 -11.11882,6.13186 -16.55882,9.49279c-2.792,-0.97105 -5.57873,-1.77704 -8.15298,-2.57601c2.2336,-0.89555 4.00889,-1.55579 5.75608,-2.23009c3.05188,-1.1765 7.01687,-2.7042 10.98537,-4.24067c7.94051,-3.06944 15.92667,-6.16346 16.62028,-6.43037l0.05619,-0.02283l0.05268,-0.02283c0.19316,-0.0878 0.30378,-0.09658 0.35471,-0.10009c0,0 -0.01756,-0.05795 -0.00351,-0.04566l-0.00176,0zm-20.91715,22.0638l2.16687,1.60145c-0.93418,0.91311 -1.81743,1.77353 -2.45485,2.38812l0.28798,-3.98957"
                                fill="white"></path>
                        </svg>
                    </a>
                </div>
                <div class="mt-6"><button @click="$store.modalshare.open = false" type="button" class="inline-flex items-center justify-center rounded-full text-sm font-medium dark:border-slate-500 dark:text-white border h-10 px-4 py-2 w-full">Cancel</button></div>
            </div>
        </div>
    </div>

</main>

@include('layouts.landing.footer')
@endsection

@push('js')
    <script src="{!! asset('assets/clipboard.min.js') !!}"></script>
    <script src="{{ asset('assets/highlight/highlight.min.js?v=1') }}"></script>
    <script>
        var clipboard = new ClipboardJS('.copy-link');
        clipboard.on('success', function(e) {
            toast.toast({
                style: `<svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-sky-400" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M17 3.34a10 10 0 1 1 -14.995 8.984l-.005 -.324l.005 -.324a10 10 0 0 1 14.995 -8.336zm-1.8 10.946a1 1 0 0 0 -1.414 .014a2.5 2.5 0 0 1 -3.572 0a1 1 0 0 0 -1.428 1.4a4.5 4.5 0 0 0 6.428 0a1 1 0 0 0 -.014 -1.414zm-6.19 -5.286l-.127 .007a1 1 0 0 0 .117 1.993l.127 -.007a1 1 0 0 0 -.117 -1.993zm6 0l-.127 .007a1 1 0 0 0 .117 1.993l.127 -.007a1 1 0 0 0 -.117 -1.993z" stroke-width="0" fill="currentColor"></path></svg>`,
                title: 'Link Copied.',
                msg: 'Link copied to clipboard. You can paste it anywhere now.',
            })
        });
        clipboard.on('error', function(e) {
            console.log(e);
        });

        // alpinejs
        document.addEventListener('alpine:init', () => {
            Alpine.store('modalshare', false)
        })

        var toasterror = 0;
        document.querySelectorAll('.btn-react').forEach(btn => {
            btn.addEventListener('click', (react) => {
                let reactType = react.target.dataset.react;
                axios.post("{!! route('blog.react.axios') !!}", {
                    react: reactType,
                    blog_id: "{!! $row->id !!}",
                }).then((res) => {
                    let count = document.querySelector(`#count-${reactType}`);
                    count.innerHTML = parseInt(count.innerHTML) + 1;
                }).catch((err) => {
                    if(err.response.data.type=='limit'){
                        if(toasterror >= 2) return;
                        toasterror++;
                        toast.toast({
                            style: `info`,
                            title: 'Limit Reached.',
                            msg: 'You have reached the maximum limit of reactions for this article.',
                        })
                    }
                })
            })
        })

        hljs.highlightAll();
        document.querySelectorAll('pre').forEach((preElement) => {
            const firstDivElement = document.createElement('div');
            firstDivElement.className = 'overflow-hidden rounded-md shadow-2xl mb-3 border dark:border-none';
            preElement.parentElement.insertBefore(firstDivElement, preElement);
            const additionalCodeDiv = document.createElement('div');
            additionalCodeDiv.className = 'bg-slate-100 dark:bg-slate-700 flex items-center py-3 px-3 gap-x-1';
            additionalCodeDiv.innerHTML = '<div class="p-[5px] bg-red-600 inline-block rounded-full"></div><div class="p-[5px] bg-yellow-600 inline-block rounded-full"></div><div class="p-[5px] bg-green-600 inline-block rounded-full"></div>';
            firstDivElement.appendChild(additionalCodeDiv);
            firstDivElement.appendChild(preElement);
        });
    </script>
@endpush

@push('css')
<link rel="stylesheet" href="{{ asset('assets/highlight/tokyo-night-dark.min.css?v=1') }}">
@endpush
