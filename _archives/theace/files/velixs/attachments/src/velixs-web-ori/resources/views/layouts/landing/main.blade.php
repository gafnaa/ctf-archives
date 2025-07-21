<!---
ACUMALAKAN
AJARIN DONG PUH SEPUH
-->

<!DOCTYPE html>
<html lang="en" data-theme="light" class="scroll-smooth">

<head>
    @isset($license_get) <meta name="license-get" content="{{ $license_get->license_key }}"> @endisset
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <meta name="base_url" content="{{ url('/') }}">
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://rsms.me/inter/inter.css">
    @include('layouts.meta')
    @vite('resources/css/app.css')
    <script>
        document.querySelector('html').setAttribute('data-theme', localStorage.getItem('theme-ilsya') ?? 'light');
    </script>
    @stack('css')
</head>

<body class="dark:bg-slate-950 bg-slate-50">
    <div id="loading-bar" class="z-20 h-[2px] rounded-xl btn-gradient fixed top-0 left-0" style="width: 0%"></div>
    <!-- navbar section start -->
    <!-- option on-scroll-static -->
    <header id="navbar" class="fixed top-0 z-10 w-full backdrop-blur flex-none transition-colors duration-500 lg:z-10 lg:border-b lg:border-slate-900/10 dark:lg:border-slate-500/10 border-none">
        <div class="mx-auto lg:max-w-screen-2xl"> {{-- lg:max-w-screen-2xl --}}
            <div class="py-3 border-b border-slate-900/10 lg:px-8 lg:border-0 dark:border-slate-300/10 mx-4 lg:mx-0">
                <div class="relative flex items-center">
                    <a class="mr-3 flex-none w-[2.0625rem] overflow-hidden md:w-auto" href="{{ route('main') }}">
                        <span class="sr-only">Ilsya Home page</span>
                        <img src="{!! $ws->_logo() !!}" class="h-9" alt="">
                    </a>
                    <button data-quick-access="click" class="ml-3 text-xs leading-5 font-medium text-primary-600 dark:text-primary-400 bg-primary-400/10 rounded-full py-1 px-3 flex items-center hover:bg-primary-400/20">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                            <path d="M4 4m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z"></path>
                            <path d="M14 4m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z"></path>
                            <path d="M4 14m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z"></path>
                            <path d="M14 17h6m-3 -3v6"></path>
                        </svg>
                        <div class="flex xl:flex md:hidden lg:hidden items-center">
                            <span class="mt-[1.2px] ml-2 ">Quick Center</span>
                            <svg width="3" height="6" class="ml-3 mt-[2px] overflow-visible block text-primary-300 dark:text-primary-400" aria-hidden="true">
                                <path d="M0 0L3 3L0 6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"></path>
                            </svg>
                        </div>
                    </button>
                    <div class="relative hidden md:flex items-center ml-auto">
                        <nav class="text-[13px] leading-6 font-semibold text-slate-600 dark:text-slate-200">
                            <ul class="flex space-x-7">
                                <li><a class="hover:text-primary-500 dark:hover:text-primary-400" href="{!! route('main') !!}">Home</a></li>
                                <li><a class="hover:text-primary-500 dark:hover:text-primary-400" href="{!! route('product') !!}">Projects</a></li>
                                <li class="relative" x-data="{ dropdown: false }">
                                    <a href="javascript:void(0)" x-on:click="dropdown =! dropdown" class="group inline-flex items-center hover:text-primary-500 dark:hover:text-primary-400">
                                        <span>Blog</span>
                                        <svg x-bind:class="dropdown ? 'animate-bounce -mb-2' : ''" class="transition-transform text-gray-400 ml-1 -mr-3 h-4 w-4 group-hover:text-primary-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                            <path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clip-rule="evenodd" />
                                        </svg>
                                    </a>
                                    <div x-show="dropdown" @click.outside="dropdown = false" x-transition class="absolute left-[-500%] z-10 mt-3 w-screen max-w-max transition-all transform" style="display: none;">
                                        <div class="w-screen max-w-md flex-auto overflow-hidden rounded-3xl bg-white dark:bg-slate-900 text-sm leading-6 shadow-lg ring-1 ring-slate-900/5 dark:ring-slate-100/5">
                                            <div class="p-4">
                                                <div class="group relative flex gap-x-6 rounded-lg p-4 hover:bg-slate-50 dark:hover:bg-slate-800">
                                                    <div class="mt-1 flex h-11 w-11 group-hover:shadow transition flex-none items-center justify-center rounded-lg bg-slate-50 dark:bg-slate-800 dark:group-hover:bg-slate-700 group-hover:bg-white">
                                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5 text-slate-600 dark:text-slate-300 group-hover:text-primary-400 dark:group-hover:text-primary-400 stroke-[1.5]" aria-hidden="true">
                                                            <path d="M4 4m0 1a1 1 0 0 1 1 -1h14a1 1 0 0 1 1 1v14a1 1 0 0 1 -1 1h-14a1 1 0 0 1 -1 -1z"></path>
                                                            <path d="M12 7v5l3 3"></path>
                                                            <path d="M4 12h1"></path>
                                                            <path d="M19 12h1"></path>
                                                            <path d="M12 19v1"></path>
                                                        </svg>
                                                    </div>
                                                    <div>
                                                        <a href="{!! route('blog') !!}" class="font-semibold text-slate-900 dark:text-slate-100 focus:outline-none">Latest<span class="absolute inset-0"></span></a>
                                                        <p class="mt-1 text-slate-600 dark:text-slate-400">The latest article published.</p>
                                                    </div>
                                                </div>
                                                <div class="group relative flex gap-x-6 rounded-lg p-4 hover:bg-slate-50 dark:hover:bg-slate-800">
                                                    <div class="mt-1 flex h-11 w-11 group-hover:shadow transition flex-none items-center justify-center rounded-lg bg-slate-50 dark:bg-slate-800 dark:group-hover:bg-slate-700 group-hover:bg-white">
                                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5 text-slate-600 dark:text-slate-300 group-hover:text-primary-400 dark:group-hover:text-primary-400 stroke-[1.5]" aria-hidden="true">
                                                            <path d="M12 12c2 -2.96 0 -7 -1 -8c0 3.038 -1.773 4.741 -3 6c-1.226 1.26 -2 3.24 -2 5a6 6 0 1 0 12 0c0 -1.532 -1.056 -3.94 -2 -5c-1.786 3 -2.791 3 -4 2z"></path>
                                                        </svg>
                                                    </div>
                                                    <div><a href="{!! route('blog.sort','popular') !!}" class="font-semibold text-slate-900 dark:text-slate-100 focus:outline-none">Popular<span class="absolute inset-0"></span></a>
                                                        <p class="mt-1 text-slate-600 dark:text-slate-400">The most popular articles all the time</p>
                                                    </div>
                                                </div>
                                                <div class="group relative flex gap-x-6 rounded-lg p-4 hover:bg-slate-50 dark:hover:bg-slate-800">
                                                    <div class="mt-1 flex h-11 w-11 group-hover:shadow transition flex-none items-center justify-center rounded-lg bg-slate-50 dark:bg-slate-800 dark:group-hover:bg-slate-700 group-hover:bg-white">
                                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5 text-slate-600 dark:text-slate-300 group-hover:text-primary-400 dark:group-hover:text-primary-400 stroke-[1.5]" aria-hidden="true">
                                                            <path d="M19.5 12.572l-7.5 7.428l-7.5 -7.428a5 5 0 1 1 7.5 -6.566a5 5 0 1 1 7.5 6.572"></path>
                                                        </svg>
                                                    </div>
                                                    <div>
                                                        <a href="{!! route('blog.sort','trending') !!}" class="font-semibold text-slate-900 dark:text-slate-100 focus:outline-none">Trending<span class="absolute inset-0"></span></a>
                                                        <p class="mt-1 text-slate-600 dark:text-slate-400">The most trending article in the last 7 days</p>
                                                    </div>
                                                </div>
                                                <div class="group relative flex gap-x-6 rounded-lg p-4 hover:bg-slate-50 dark:hover:bg-slate-800">
                                                    <div class="mt-1 flex h-11 w-11 group-hover:shadow transition flex-none items-center justify-center rounded-lg bg-slate-50 dark:bg-slate-800 dark:group-hover:bg-slate-700 group-hover:bg-white">
                                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5 text-slate-600 dark:text-slate-300 group-hover:text-primary-600 dark:group-hover:text-primary-400 stroke-[1.5]" aria-hidden="true">
                                                            <path d="M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0"></path>
                                                            <path d="M12 7v5l3 3"></path>
                                                        </svg>
                                                    </div>
                                                    <div>
                                                        <a href="{!! route('blog.sort','popular-month') !!}" class="font-semibold text-slate-900 dark:text-slate-100 focus:outline-none">Popular this month<span class="absolute inset-0"></span></a>
                                                        <p class="mt-1 text-slate-600 dark:text-slate-400">Most viewed articles this month</p>
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="bg-slate-50 dark:bg-slate-800/50 p-8">
                                                <div class="flex justify-between">
                                                    <h3 class="text-sm font-semibold leading-6 text-slate-500 dark:text-slate-400">Recent posts</h3><a href="{!! route('blog') !!}" class="focus:outline-none text-sm font-semibold leading-6 text-primary-400 dark:text-primary-400">See all <span aria-hidden="true">→</span></a>
                                                </div>
                                                <ul role="list" class="mt-6 space-y-6">
                                                    @foreach ($recent_posts as $recent_post)
                                                    <li class="relative"><time datetime="{{ $recent_post->created_at->format('Y-m-d') }}" class="block text-xs leading-6 text-slate-600 dark:text-slate-400">{{ $recent_post->created_at->format('M d, Y') }}</time><a href="{!! route('blog.detail',$recent_post->slug) !!}" class="focus:outline-none block truncate text-sm font-semibold leading-6 text-slate-900 dark:text-slate-100">{{ $recent_post->title }}<span class="absolute inset-0"></span></a></li>
                                                    @endforeach
                                                </ul>
                                            </div>
                                        </div>
                                    </div>
                                </li>
                                <li class="relative">
                                    <div class="absolute p-[3px] top-[0.3rem] right-[-2px] animate-ping dark:bg-primary-50 bg-primary-600 rounded-full inline-block"></div>
                                    <a class="hover:text-primary-500 dark:hover:text-primary-400" href="{!! route('rapi') !!}">Rest API</a>
                                </li>
                                <li class="relative" x-data="{ dropdown: false }">
                                    <a x-on:click="dropdown =! dropdown" class="group inline-flex items-center hover:text-primary-500 dark:hover:text-primary-400" href="javascript:void(0)">
                                        Pages
                                        <svg x-bind:class="dropdown ? 'animate-bounce -mb-2' : ''" class="transition-transform text-gray-400 ml-1 -mr-3 h-4 w-4 group-hover:text-primary-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                            <path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clip-rule="evenodd" />
                                        </svg>
                                    </a>

                                    <div class="absolute left-0 z-10 mt-3 w-screen max-w-md -translate-x-1/2 transform px-2 sm:px-0">
                                        <div x-show="dropdown" @click.outside="dropdown = false" x-transition style="display: none" class="w-screen max-w-md flex-auto overflow-hidden rounded-3xl bg-white dark:bg-slate-900 text-sm leading-6 shadow-lg ring-1 ring-slate-900/5 dark:ring-slate-100/5">
                                            <div class="p-4">
                                                <a href="{{ route('pricing') }}" class="group relative flex gap-x-6 rounded-lg p-4 hover:bg-slate-50 dark:hover:bg-slate-800">
                                                    <div class="mt-1 flex h-11 w-11 group-hover:shadow transition flex-none items-center justify-center rounded-lg bg-slate-50 dark:bg-slate-800 dark:group-hover:bg-slate-700 group-hover:bg-white">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-slate-600 dark:text-slate-300 group-hover:text-primary-400 dark:group-hover:text-primary-400 stroke-[1.5]" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                            <path d="M10 13l2.5 0c2.5 0 5 -2.5 5 -5c0 -3 -1.9 -5 -5 -5h-5.5c-.5 0 -1 .5 -1 1l-2 14c0 .5 .5 1 1 1h2.8l1.2 -5c.1 -.6 .4 -1 1 -1zm7.5 -5.8c1.7 1 2.5 2.8 2.5 4.8c0 2.5 -2.5 4.5 -5 4.5h-2.6l-.6 3.6a1 1 0 0 1 -1 .8l-2.7 0a.5 .5 0 0 1 -.5 -.6l.2 -1.4"></path>
                                                        </svg>
                                                    </div>
                                                    <div>
                                                        <p class="font-semibold text-slate-900 dark:text-slate-100 focus:outline-none">Pricing</p>
                                                        <p class="mt-1 text-slate-600 dark:text-slate-400 text-sm font-normal">Paket layanan yang fleksibel dan disesuaikan dengan kebutuhan Anda.</p>
                                                    </div>
                                                </a>
                                                <a href="{{ route('whatsapp.programmer') }}" class="group relative flex gap-x-6 rounded-lg p-4 hover:bg-slate-50 dark:hover:bg-slate-800">
                                                    <div class="mt-1 flex h-11 w-11 group-hover:shadow transition flex-none items-center justify-center rounded-lg bg-slate-50 dark:bg-slate-800 dark:group-hover:bg-slate-700 group-hover:bg-white">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-slate-600 dark:text-slate-300 group-hover:text-primary-400 dark:group-hover:text-primary-400 stroke-[1.5]" viewBox="0 0 24 24" stroke-width="3" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                            <path d="M3 21l1.65 -3.8a9 9 0 1 1 3.4 2.9l-5.05 .9"></path>
                                                            <path d="M9 10a.5 .5 0 0 0 1 0v-1a.5 .5 0 0 0 -1 0v1a5 5 0 0 0 5 5h1a.5 .5 0 0 0 0 -1h-1a.5 .5 0 0 0 0 1"></path>
                                                        </svg>
                                                    </div>
                                                    <div>
                                                        <p class="font-semibold text-slate-900 dark:text-slate-100 focus:outline-none">Whatsapp Group Programmer</p>
                                                        <p class="mt-1 text-slate-600 dark:text-slate-400 text-sm font-normal">Kumpulan group whatsapp programmer indonesia.</p>
                                                    </div>
                                                </a>
                                                <a href="{{ route('contact') }}" class="group relative flex gap-x-6 rounded-lg p-4 hover:bg-slate-50 dark:hover:bg-slate-800">
                                                    <div class="mt-1 flex h-11 w-11 group-hover:shadow transition flex-none items-center justify-center rounded-lg bg-slate-50 dark:bg-slate-800 dark:group-hover:bg-slate-700 group-hover:bg-white">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-slate-600 dark:text-slate-300 group-hover:text-primary-400 dark:group-hover:text-primary-400 stroke-[1.5]" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                            <path d="M20 6v12a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2z"></path>
                                                            <path d="M10 16h6"></path>
                                                            <path d="M13 11m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0"></path>
                                                            <path d="M4 8h3"></path>
                                                            <path d="M4 12h3"></path>
                                                            <path d="M4 16h3"></path>
                                                        </svg>
                                                    </div>
                                                    <div>
                                                        <p class="font-semibold text-slate-900 dark:text-slate-100 focus:outline-none">Contact</p>
                                                        <p class="mt-1 text-slate-600 dark:text-slate-400 text-sm font-normal">Tim kami siap membantu Anda dengan pertanyaan atau permintaan apa pun yang Anda miliki.</p>
                                                    </div>
                                                </a>
                                            </div>
                                            <div class="bg-slate-50 dark:bg-slate-800 p-5 sm:p-8">
                                                <a href="{{ route('rapi') }}" class="-m-3 flow-root rounded-md p-3 transition duration-150 ease-in-out">
                                                    <span class="flex items-center">
                                                        <span class="text-base text-gray-900 dark:text-slate-50">API Hub</span>
                                                        <span class="ml-3 inline-flex items-center rounded-full bg-primary-100 dark:bg-primary-600/50 px-3 py-0.5 text-xs font-medium leading-5 text-primary-600 dark:text-primary-50">New</span>
                                                    </span>
                                                    <span class="mt-1 block text-xs text-slate-500 dark:text-slate-400">Kami menyediakan berbagai API untuk memenuhi kebutuhan aplikasi Anda.</span>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                </li>
                            </ul>
                        </nav>
                        <!-- profile -->
                        <div class="border-l border-slate-300 ml-6 pl-4 dark:border-slate-600">
                            <div class="flex space-x-5">
                                <div class="flex items-center gap-x-2">
                                    <button type="button" data-btn-search="" class="w-8 h-8 flex items-center justify-center hover:text-slate-600 dark:text-slate-400 dark:hover:text-slate-300">
                                        <span class="sr-only">Search</span>
                                        <svg width="25" height="25" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                            <path d="m19 19-3.5-3.5"></path>
                                            <circle cx="11" cy="11" r="6"></circle>
                                        </svg>
                                    </button>
                                    <div class="relative">
                                        <button data-switch-theme="" class="grid h-8 w-8 place-content-center rounded-full focus:outline-none hover:text-slate-600 dark:text-slate-400 dark:hover:text-slate-300" type="button">
                                            <span class="sr-only">Switch Dark or Light Mode</span>
                                            <svg data-active-theme="dark" xmlns="http://www.w3.org/2000/svg" class="hidden animate-bounce-in" width="20" height="20" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M12 3c.132 0 .263 0 .393 0a7.5 7.5 0 0 0 7.92 12.446a9 9 0 1 1 -8.313 -12.454z"></path>
                                            </svg>
                                            <svg data-active-theme="light" xmlns="http://www.w3.org/2000/svg" class="animate-bounce-in" width="20" height="20" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M14.828 14.828a4 4 0 1 0 -5.656 -5.656a4 4 0 0 0 5.656 5.656z"></path>
                                                <path d="M6.343 17.657l-1.414 1.414"></path>
                                                <path d="M6.343 6.343l-1.414 -1.414"></path>
                                                <path d="M17.657 6.343l1.414 -1.414"></path>
                                                <path d="M17.657 17.657l1.414 1.414"></path>
                                                <path d="M4 12h-2"></path>
                                                <path d="M12 4v-2"></path>
                                                <path d="M20 12h2"></path>
                                                <path d="M12 20v2"></path>
                                            </svg>
                                        </button>
                                    </div>
                                </div>
                                @if ($auth)
                                <a class="inline-flex items-center justify-center text-sm font-medium bg-slate-900 dark:btn-gradient text-slate-50 h-9 rounded-full px-4" href="{{ route('dash') }}">Dashbords</a>
                                @else
                                <a class="inline-flex items-center justify-center text-sm font-medium bg-slate-900 dark:btn-gradient text-slate-50 h-9 rounded-full px-4" href="{{ route('login') }}">Login</a>
                                @endif
                            </div>
                        </div>
                    </div>
                    <button type="button" data-btn-search="" class="ml-auto text-slate-500 w-8 h-8 -my-1 flex items-center justify-center hover:text-slate-600 md:hidden dark:text-slate-400 dark:hover:text-slate-300">
                        <span class="sr-only">Search</span>
                        <svg width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                            <path d="m19 19-3.5-3.5"></path>
                            <circle cx="11" cy="11" r="6"></circle>
                        </svg>
                    </button>
                </div>
            </div>
        </div>
    </header>

    <div x-data x-show="$store.navbarSlide.open" class="relative z-50" aria-labelledby="slide-over-title" role="dialog" aria-modal="true" style="display: none">
        <div x-show="$store.navbarSlide.open" x-transition.opacity class="fixed inset-0 bg-white dark:bg-slate-900/25 backdrop-blur-sm bg-opacity-75 transition-opacity"></div>
        <div class="fixed inset-0 overflow-hidden">
            <div class="absolute inset-0 overflow-hidden">
                <div class="pointer-events-none fixed inset-y-0 left-0 flex max-w-full pr-10">
                    <div class="pointer-events-auto w-screen max-w-md">
                        <div class="flex h-full flex-col bg-white dark:bg-slate-900 py-3 shadow-xl animate-fade-in-left-bounce" x-show="$store.navbarSlide.open" @click.outside="$store.navbarSlide.open = false" x-transition:leave="transition ease-in duration-300" x-transition:leave-start="transform translate-x-0" x-transition:leave-end="transform translate-x-[-100%]">
                            <div class="px-4 sm:px-6">
                                <div class="flex items-start justify-between">
                                    <img class="h-10" src="{{ $ws->_logo() }}" alt="{{ $ws->meta_title }}">
                                    <div class="ml-3 flex h-7 items-center">
                                        <button type="button" x-on:click="$store.navbarSlide.open = false" class="rounded-lg p-1 bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-400">
                                            <span class="sr-only">Close panel</span>
                                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" class="h-4 w-4">
                                                <path stroke="currentColor" stroke-linecap="round" stroke-width="2" d="m7.75 7.75 8.5 8.5m0-8.5-8.5 8.5"></path>
                                            </svg>
                                        </button>
                                    </div>
                                </div>
                            </div>
                            <div class="flex flex-1 flex-col mt-6 px-4 sm:px-6 overflow-y-scroll">
                                <div class="dark:text-white">
                                    <ul class="space-y-1">
                                        <li class="-mx-2 text-xs">
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('main') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M19.072 21h-14.144a1.928 1.928 0 0 1 -1.928 -1.928v-6.857c0 -.512 .203 -1 .566 -1.365l7.07 -7.063a1.928 1.928 0 0 1 2.727 0l7.071 7.063c.363 .362 .566 .853 .566 1.365v6.857a1.928 1.928 0 0 1 -1.928 1.928z"></path>
                                                        <path d="M7 13v4h10v-4l-5 -5"></path>
                                                        <path d="M14.8 5.2l-11.8 11.8"></path>
                                                        <path d="M7 17v4"></path>
                                                        <path d="M17 17v4"></path>
                                                    </svg>
                                                    <span>Home</span>
                                                </div>
                                            </a>
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('product') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M12 3l8 4.5l0 9l-8 4.5l-8 -4.5l0 -9l8 -4.5"></path>
                                                        <path d="M12 12l8 -4.5"></path>
                                                        <path d="M12 12l0 9"></path>
                                                        <path d="M12 12l-8 -4.5"></path>
                                                    </svg>
                                                    <span>Projects</span>
                                                </div>
                                            </a>
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('blog') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M8 21h8a5 5 0 0 0 5 -5v-3a3 3 0 0 0 -3 -3h-1v-2a5 5 0 0 0 -5 -5h-4a5 5 0 0 0 -5 5v8a5 5 0 0 0 5 5z"></path>
                                                        <path d="M7 7m0 1.5a1.5 1.5 0 0 1 1.5 -1.5h3a1.5 1.5 0 0 1 1.5 1.5v0a1.5 1.5 0 0 1 -1.5 1.5h-3a1.5 1.5 0 0 1 -1.5 -1.5z"></path>
                                                        <path d="M7 14m0 1.5a1.5 1.5 0 0 1 1.5 -1.5h7a1.5 1.5 0 0 1 1.5 1.5v0a1.5 1.5 0 0 1 -1.5 1.5h-7a1.5 1.5 0 0 1 -1.5 -1.5z"></path>
                                                    </svg>
                                                    <span>Blog</span>
                                                </div>
                                            </a>
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('rapi') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M12 12c2 -2.96 0 -7 -1 -8c0 3.038 -1.773 4.741 -3 6c-1.226 1.26 -2 3.24 -2 5a6 6 0 1 0 12 0c0 -1.532 -1.056 -3.94 -2 -5c-1.786 3 -2.791 3 -4 2z"></path>
                                                    </svg>
                                                    <span>Rest API</span>
                                                </div>
                                            </a>
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('contact') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M20 6v12a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2z"></path>
                                                        <path d="M10 16h6"></path>
                                                        <path d="M13 11m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0"></path>
                                                        <path d="M4 8h3"></path>
                                                        <path d="M4 12h3"></path>
                                                        <path d="M4 16h3"></path>
                                                    </svg>
                                                    <span>Contacts</span>
                                                </div>
                                            </a>
                                        </li>
                                    </ul>
                                    <div data-orientation="horizontal" role="none" class="shrink-0 h-[1px] rounded-full w-full my-2 bg-gradient-to-r from-slate-300 dark:from-slate-800 to-transparent"></div>
                                    <ul class="space-y-1">
                                        <div class="flex justify-between mb-2 text-slate-500">
                                            <div class="text-[11px]">Pages</div>
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M10 10m-7 0a7 7 0 1 0 14 0a7 7 0 1 0 -14 0"></path>
                                                <path d="M21 21l-6 -6"></path>
                                            </svg>
                                        </div>
                                        <li class="-mx-2 text-xs">
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('pricing') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M10 13l2.5 0c2.5 0 5 -2.5 5 -5c0 -3 -1.9 -5 -5 -5h-5.5c-.5 0 -1 .5 -1 1l-2 14c0 .5 .5 1 1 1h2.8l1.2 -5c.1 -.6 .4 -1 1 -1zm7.5 -5.8c1.7 1 2.5 2.8 2.5 4.8c0 2.5 -2.5 4.5 -5 4.5h-2.6l-.6 3.6a1 1 0 0 1 -1 .8l-2.7 0a.5 .5 0 0 1 -.5 -.6l.2 -1.4"></path>
                                                    </svg>
                                                    <span>Pricing</span>
                                                </div>
                                            </a>
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('whatsapp.programmer') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M3 21l1.65 -3.8a9 9 0 1 1 3.4 2.9l-5.05 .9"></path>
                                                        <path d="M9 10a.5 .5 0 0 0 1 0v-1a.5 .5 0 0 0 -1 0v1a5 5 0 0 0 5 5h1a.5 .5 0 0 0 0 -1h-1a.5 .5 0 0 0 0 1"></path>
                                                    </svg>
                                                    <span>WA Group Programmer</span>
                                                </div>
                                            </a>
                                        </li>
                                    </ul>
                                    <div data-orientation="horizontal" role="none" class="shrink-0 h-[1px] rounded-full w-full my-2 bg-gradient-to-r from-slate-300 dark:from-slate-800 to-transparent"></div>
                                    <ul class="space-y-1">
                                        <li class="-mx-2 text-xs">
                                            @if ($auth)
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('dash') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M4 4m0 2a2 2 0 0 1 2 -2h12a2 2 0 0 1 2 2v12a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2z"></path>
                                                        <path d="M10 4l4 16"></path>
                                                        <path d="M12 12l-8 2"></path>
                                                    </svg>
                                                    <span>Dashboards</span>
                                                </div>
                                            </a>
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('dash') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M12 13a3 3 0 1 0 0 -6a3 3 0 0 0 0 6z"></path>
                                                        <path d="M6.201 18.744a4 4 0 0 1 3.799 -2.744h4a4 4 0 0 1 3.798 2.741"></path>
                                                        <path d="M19.875 6.27c.7 .398 1.13 1.143 1.125 1.948v7.284c0 .809 -.443 1.555 -1.158 1.948l-6.75 4.27a2.269 2.269 0 0 1 -2.184 0l-6.75 -4.27a2.225 2.225 0 0 1 -1.158 -1.948v-7.285c0 -.809 .443 -1.554 1.158 -1.947l6.75 -3.98a2.33 2.33 0 0 1 2.25 0l6.75 3.98h-.033z"></path>
                                                    </svg>
                                                    <span>My Profile</span>
                                                </div>
                                            </a>
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('dash.purchases') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M17 8v-3a1 1 0 0 0 -1 -1h-10a2 2 0 0 0 0 4h12a1 1 0 0 1 1 1v3m0 4v3a1 1 0 0 1 -1 1h-12a2 2 0 0 1 -2 -2v-12"></path>
                                                        <path d="M20 12v4h-4a2 2 0 0 1 0 -4h4"></path>
                                                    </svg>
                                                    <span>Purchases</span>
                                                </div>
                                            </a>
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('dash.personal') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M19.875 6.27a2.225 2.225 0 0 1 1.125 1.948v7.284c0 .809 -.443 1.555 -1.158 1.948l-6.75 4.27a2.269 2.269 0 0 1 -2.184 0l-6.75 -4.27a2.225 2.225 0 0 1 -1.158 -1.948v-7.285c0 -.809 .443 -1.554 1.158 -1.947l6.75 -3.98a2.33 2.33 0 0 1 2.25 0l6.75 3.98h-.033z"></path>
                                                        <path d="M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0"></path>
                                                    </svg>
                                                    <span>Settings</span>
                                                </div>
                                            </a>
                                            @else
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('login') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M12 13a3 3 0 1 0 0 -6a3 3 0 0 0 0 6z"></path>
                                                        <path d="M6.201 18.744a4 4 0 0 1 3.799 -2.744h4a4 4 0 0 1 3.798 2.741"></path>
                                                        <path d="M19.875 6.27c.7 .398 1.13 1.143 1.125 1.948v7.284c0 .809 -.443 1.555 -1.158 1.948l-6.75 4.27a2.269 2.269 0 0 1 -2.184 0l-6.75 -4.27a2.225 2.225 0 0 1 -1.158 -1.948v-7.285c0 -.809 .443 -1.554 1.158 -1.947l6.75 -3.98a2.33 2.33 0 0 1 2.25 0l6.75 3.98h-.033z"></path>
                                                    </svg>
                                                    <span>Login</span>
                                                </div>
                                            </a>
                                            <a class="group block w-full text-left focus:outline-none" href="{{ route('register') }}">
                                                <div class="inline-flex w-auto items-center justify-start rounded-xl py-2 pr-4 text-left font-medium duration-200 group-hover:bg-muted pl-3">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-3" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0"></path>
                                                        <path d="M10 15v-6h2a2 2 0 1 1 0 4h-2"></path>
                                                        <path d="M14 15l-2 -2"></path>
                                                    </svg>
                                                    <span>Register</span>
                                                </div>
                                            </a>
                                            @endif
                                        </li>
                                    </ul>
                                </div>
                            </div>
                            <div class="flex flex-shrink-0 px-4">
                                @if ($auth)
                                    <a href="{{ route('profile',$auth->username) }}" class="text-gray-900 w-full group my-2 flex items-center px-4 py-5 text-sm font-medium ilsya-scale-105 rounded-xl bg-gray-200/60 dark:bg-gray-800">
                                        <img class="h-11 w-11 inline-block rounded-full mr-2.5" src="{!! $auth->_avatar() !!}" alt="">
                                        <div>
                                            <div class="line-clamp-1 dark:text-white text-sm font-normal">{{ $auth->name }}</div>
                                            <div class="text-xs text-gray-500 line-clamp-1 dark:text-gray-400">{{ __("@".$auth->username) }}</div>
                                        </div>
                                    </a>
                                @endif
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- navbar section end -->
    @yield('content')

    <div class="md:my-0 my-16"></div>

    @if(!isset($page_product_detail))
    <div>
        <div class="fixed z-20 w-full border-t dark:border-t-0 bottom-0 md:hidden block backdrop-blur bg-white/90 dark:bg-gray-900/90 px-3 py-2 transition-transform transform animate-footer-product">
            <div class=""> {{-- px-3 --}}
                <div class="text-slate-600 dark:text-slate-200 grid h-full max-w-lg grid-cols-5 mx-auto">
                    <a href="{!! route('main') !!}" class="inline-flex flex-col items-center justify-center px-5">
                        <div class="sr-only">Home</div>
                        <svg xmlns="http://www.w3.org/2000/svg" width="21" height="21" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                            <path d="M19.072 21h-14.144a1.928 1.928 0 0 1 -1.928 -1.928v-6.857c0 -.512 .203 -1 .566 -1.365l7.07 -7.063a1.928 1.928 0 0 1 2.727 0l7.071 7.063c.363 .362 .566 .853 .566 1.365v6.857a1.928 1.928 0 0 1 -1.928 1.928z"></path>
                            <path d="M7 13v4h10v-4l-5 -5"></path>
                            <path d="M14.8 5.2l-11.8 11.8"></path>
                            <path d="M7 17v4"></path>
                            <path d="M17 17v4"></path>
                        </svg><span class="text-[10px]">Home</span>
                    </a>
                    <a href="{!! route('product') !!}" class="inline-flex flex-col items-center justify-center px-5">
                        <div class="sr-only">Projects</div>
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                            <path d="M4 8v-2a2 2 0 0 1 2 -2h2"></path>
                            <path d="M4 16v2a2 2 0 0 0 2 2h2"></path>
                            <path d="M16 4h2a2 2 0 0 1 2 2v2"></path>
                            <path d="M16 20h2a2 2 0 0 0 2 -2v-2"></path>
                            <path d="M12 12.5l4 -2.5"></path>
                            <path d="M8 10l4 2.5v4.5l4 -2.5v-4.5l-4 -2.5z"></path>
                            <path d="M8 10v4.5l4 2.5"></path>
                        </svg><span class="text-[10px]">Projects</span>
                    </a>
                    <a href="{!! route('rapi') !!}" class="inline-flex flex-col items-center justify-center px-5">
                        <div class="sr-only">Apihub</div>
                        <svg xmlns="http://www.w3.org/2000/svg" width="21" height="21" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                            <path d="M12 12c2 -2.96 0 -7 -1 -8c0 3.038 -1.773 4.741 -3 6c-1.226 1.26 -2 3.24 -2 5a6 6 0 1 0 12 0c0 -1.532 -1.056 -3.94 -2 -5c-1.786 3 -2.791 3 -4 2z"></path>
                         </svg><span class="text-[10px]">APIHub</span>
                    </a>
                    <button data-switch-theme="" class="inline-flex flex-col items-center justify-center px-5">
                        <div class="sr-only">darklight</div>
                        <svg data-active-theme="dark" xmlns="http://www.w3.org/2000/svg" class="hidden" width="21" height="21" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                            <path d="M12 3c.132 0 .263 0 .393 0a7.5 7.5 0 0 0 7.92 12.446a9 9 0 1 1 -8.313 -12.454z"></path>
                        </svg>
                        <svg data-active-theme="light" xmlns="http://www.w3.org/2000/svg" class="" width="21" height="21" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                            <path d="M14.828 14.828a4 4 0 1 0 -5.656 -5.656a4 4 0 0 0 5.656 5.656z"></path>
                            <path d="M6.343 17.657l-1.414 1.414"></path>
                            <path d="M6.343 6.343l-1.414 -1.414"></path>
                            <path d="M17.657 6.343l1.414 -1.414"></path>
                            <path d="M17.657 17.657l1.414 1.414"></path>
                            <path d="M4 12h-2"></path>
                            <path d="M12 4v-2"></path>
                            <path d="M20 12h2"></path>
                            <path d="M12 20v2"></path>
                        </svg><span class="text-[10px]">Theme</span>
                    </button>
                    <a href="javascript:void(0)" x-data x-on:click="$store.navbarSlide.toggle()" class="inline-flex flex-col items-center justify-center px-5">
                        <div class="sr-only">Menu</div>
                        <svg xmlns="http://www.w3.org/2000/svg" width="21" height="21" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                            <path d="M4 4h6v6h-6z"></path>
                            <path d="M14 4h6v6h-6z"></path>
                            <path d="M4 14h6v6h-6z"></path>
                            <path d="M17 17m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0"></path>
                        </svg><span class="text-[10px]">Menu</span>
                    </a>
                </div>
            </div>
        </div>
    </div>
    @endif
    <div id="quick-access" class="hidden transition-opacity opacity-0 duration-100 ease-in-out">
        <div data-headlessui-portal="">
            <div>
                <div class="relative z-[1001]">
                    <div class="fixed inset-0 z-[-1] dark:bg-slate-900/70 bg-slate-300/50 backdrop-blur"></div>
                    <div class="fixed inset-0">
                        <div>
                            <div class="pointer-events-none absolute inset-x-4 top-8 flex justify-end sm:inset-x-8">
                                <button type="button" data-quick-access="close" class="pointer-events-auto ml-1 flex h-9 w-9 items-center justify-center rounded-xl bg-slate-300/50 text-slate-800 hover:bg-slate-300/70 sm:ml-0 dark:bg-slate-800/50 dark:text-slate-100 dark:hover:bg-slate-700/50" aria-label="Close Quick Access" title="Close Quick Access"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="h-5 w-5">
                                        <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"></path>
                                    </svg>
                                </button>
                            </div>
                            <div class="fixed left-2 right-2 bottom-0 top-20 flex flex-col gap-6 sm:left-auto sm:right-6 sm:top-24 sm:w-[320px]">
                                <!-- action center -->
                                <div class="dark:text-slate-200">
                                    <div class="flex flex-col gap-2">
                                        <div class="px-2 text-xl font-bold transform transition-all opacity-0 -translate-y-3 duration-200 ease-in-out" data-list-translate="-y">Action Center</div>
                                        <div class="flex flex-1 flex-col gap-8 p-2 transform transition-all opacity-0 -translate-y-3 duration-200 ease-in-out" data-list-translate="-y">
                                            <div class="flex h-24 gap-4">
                                                <button type="button" data-switch-theme="" class="relative flex flex-1 flex-col justify-between overflow-hidden rounded-xl p-4 transition-colors dark:bg-[#1d263a] bg-white/50">
                                                    <div class="">
                                                        <div class="absolute top-4 left-4 h-36 w-36 rounded-full" style="transform: none;">
                                                            <div class="absolute dark:hidden block">
                                                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" role="img" fill="currentColor" class="h-5 w-5">
                                                                    <path d="M10 2a.75.75 0 01.75.75v1.5a.75.75 0 01-1.5 0v-1.5A.75.75 0 0110 2zM10 15a.75.75 0 01.75.75v1.5a.75.75 0 01-1.5 0v-1.5A.75.75 0 0110 15zM10 7a3 3 0 100 6 3 3 0 000-6zM15.657 5.404a.75.75 0 10-1.06-1.06l-1.061 1.06a.75.75 0 001.06 1.06l1.06-1.06zM6.464 14.596a.75.75 0 10-1.06-1.06l-1.06 1.06a.75.75 0 001.06 1.06l1.06-1.06zM18 10a.75.75 0 01-.75.75h-1.5a.75.75 0 010-1.5h1.5A.75.75 0 0118 10zM5 10a.75.75 0 01-.75.75h-1.5a.75.75 0 010-1.5h1.5A.75.75 0 015 10zM14.596 15.657a.75.75 0 001.06-1.06l-1.06-1.061a.75.75 0 10-1.06 1.06l1.06 1.06zM5.404 6.464a.75.75 0 001.06-1.06l-1.06-1.06a.75.75 0 10-1.061 1.06l1.06 1.06z"></path>
                                                                </svg>
                                                            </div>
                                                            <div class="absolute dark:block hidden">
                                                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" role="img" fill="currentColor" class="h-5 w-5 -rotate-90">
                                                                    <path fill-rule="evenodd" clip-rule="evenodd"
                                                                        d="M6.45203 3.004C6.56477 3.09379 6.64926 3.21417 6.69537 3.35073C6.74148 3.48729 6.74726 3.63424 6.71203 3.774C6.37979 5.07796 6.43044 6.45006 6.8579 7.72598C7.28536 9.00191 8.07152 10.1276 9.12225 10.9682C10.173 11.8089 11.4437 12.3289 12.7824 12.4659C14.121 12.603 15.4708 12.3513 16.67 11.741C16.7985 11.6757 16.943 11.6487 17.0864 11.6634C17.2297 11.678 17.3658 11.7337 17.4784 11.8237C17.591 11.9136 17.6752 12.0342 17.7211 12.1708C17.7669 12.3074 17.7725 12.4543 17.737 12.594C17.3862 13.9713 16.6957 15.2386 15.7285 16.2801C14.7614 17.3216 13.5486 18.1039 12.201 18.5555C10.8534 19.0071 9.41402 19.1136 8.01462 18.8653C6.61523 18.6169 5.30045 18.0216 4.19056 17.1338C3.08068 16.246 2.21112 15.0941 1.66144 13.7835C1.11176 12.4728 0.899512 11.0452 1.0441 9.63132C1.18869 8.21742 1.68551 6.86236 2.48911 5.69008C3.2927 4.51781 4.37742 3.56575 5.64403 2.921C5.77246 2.85578 5.91695 2.82893 6.06024 2.84365C6.20352 2.85837 6.33954 2.91403 6.45203 3.004V3.004Z">
                                                                    </path>
                                                                    <path
                                                                        d="M14.979 1.801C14.9331 1.57494 14.8105 1.37171 14.6319 1.22573C14.4533 1.07975 14.2297 1 13.999 1C13.7684 1 13.5448 1.07975 13.3662 1.22573C13.1876 1.37171 13.0649 1.57494 13.019 1.801L12.779 2.993C12.7404 3.18663 12.6454 3.3645 12.5059 3.5042C12.3664 3.64389 12.1886 3.73916 11.995 3.778L10.803 4.016C10.5759 4.06092 10.3714 4.18328 10.2244 4.36218C10.0774 4.54109 9.99704 4.76546 9.99704 4.997C9.99704 5.22855 10.0774 5.45292 10.2244 5.63182C10.3714 5.81073 10.5759 5.93308 10.803 5.978L11.995 6.216C12.1888 6.25466 12.3668 6.34986 12.5065 6.48957C12.6462 6.62928 12.7414 6.80724 12.78 7.001L13.018 8.193C13.063 8.42015 13.1853 8.62467 13.3642 8.77166C13.5431 8.91864 13.7675 8.99899 13.999 8.99899C14.2306 8.99899 14.4549 8.91864 14.6339 8.77166C14.8128 8.62467 14.9351 8.42015 14.98 8.193L15.218 7.001C15.2567 6.80724 15.3519 6.62928 15.4916 6.48957C15.6313 6.34986 15.8093 6.25466 16.003 6.216L17.195 5.978C17.4222 5.93308 17.6267 5.81073 17.7737 5.63182C17.9207 5.45292 18.001 5.22855 18.001 4.997C18.001 4.76546 17.9207 4.54109 17.7737 4.36218C17.6267 4.18328 17.4222 4.06092 17.195 4.016L16.003 3.778C15.8093 3.73934 15.6313 3.64415 15.4916 3.50444C15.3519 3.36473 15.2567 3.18676 15.218 2.993L14.98 1.801H14.979Z">
                                                                    </path>
                                                                </svg>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div class="text-left text-[13px] font-medium dark:font-normal dark:hidden block">Dark Mode: Off</div>
                                                    <div class="text-left text-[13px] font-medium dark:font-normal dark:block hidden">Dark Mode: On</div>
                                                </button>
                                                <a href="https://github.com/ilsyaa" type="button" class="relative flex flex-1 flex-col justify-between overflow-hidden rounded-xl p-4 transition-colors dark:bg-[#1d263a] bg-white/50">
                                                    <div class="">
                                                        <div class="">
                                                            <svg viewBox="0 0 16 16" class="w-5 h-5" fill="currentColor" aria-hidden="true">
                                                                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
                                                            </svg>
                                                        </div>
                                                    </div>
                                                    <div class="text-left text-[13px] font-medium dark:font-normal">Github</div>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class=""></div>
                                <!-- recent -->
                                <div class="flex flex-1 flex-col">
                                    <div class="flex flex-1 flex-col gap-2 dark:text-slate-200">
                                        <div class="px-2 text-xl font-bold transform transition-all opacity-0 -translate-y-3 duration-200 ease-in-out" data-list-translate="-y">Notification</div>
                                        <div class="scrollbar-hide flex flex-1 basis-0 flex-col gap-2 overflow-y-auto p-2 pb-4 sm:pb-8">

                                            <div class="transform transition-all opacity-0 -translate-y-3 duration-200 ease-in-out" data-list-translate="-y">
                                                <a class="border-divider-light block rounded-xl border bg-white/60 p-4 text-[13px] dark:border-slate-800 dark:bg-slate-900/60" href="">
                                                    <div class="mb-1 flex justify-between text-xs text-slate-600 dark:text-slate-400">
                                                        <span>Time</span><span>Asia/Jakarta</span>
                                                    </div>
                                                    <div class="flex flex-wrap items-baseline gap-x-1">
                                                        <span id="clock"></span>
                                                    </div>
                                                </a>
                                            </div>

                                        </div>
                                    </div>
                                </div>

                                <div class="fixed left-8 bottom-10 hidden w-[320px] md:block border-divider-light rounded-xl border bg-white/40 p-4 text-[13px] backdrop-blur dark:border-slate-800 dark:bg-slate-900/60">
                                    <div>
                                        <div class="dark:text-slate-200">
                                            <div class="mb-4 flex items-center gap-4 text-xl font-bold">
                                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" stroke="currentColor" fill="currentColor" stroke-width="0" class="h-8 w-8">
                                                    <path d="M14 5a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h12zM2 4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2H2z"></path>
                                                    <path
                                                        d="M13 10.25a.25.25 0 0 1 .25-.25h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5a.25.25 0 0 1-.25-.25v-.5zm0-2a.25.25 0 0 1 .25-.25h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5a.25.25 0 0 1-.25-.25v-.5zm-5 0A.25.25 0 0 1 8.25 8h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5A.25.25 0 0 1 8 8.75v-.5zm2 0a.25.25 0 0 1 .25-.25h1.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-1.5a.25.25 0 0 1-.25-.25v-.5zm1 2a.25.25 0 0 1 .25-.25h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5a.25.25 0 0 1-.25-.25v-.5zm-5-2A.25.25 0 0 1 6.25 8h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5A.25.25 0 0 1 6 8.75v-.5zm-2 0A.25.25 0 0 1 4.25 8h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5A.25.25 0 0 1 4 8.75v-.5zm-2 0A.25.25 0 0 1 2.25 8h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5A.25.25 0 0 1 2 8.75v-.5zm11-2a.25.25 0 0 1 .25-.25h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5a.25.25 0 0 1-.25-.25v-.5zm-2 0a.25.25 0 0 1 .25-.25h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5a.25.25 0 0 1-.25-.25v-.5zm-2 0A.25.25 0 0 1 9.25 6h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5A.25.25 0 0 1 9 6.75v-.5zm-2 0A.25.25 0 0 1 7.25 6h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5A.25.25 0 0 1 7 6.75v-.5zm-2 0A.25.25 0 0 1 5.25 6h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5A.25.25 0 0 1 5 6.75v-.5zm-3 0A.25.25 0 0 1 2.25 6h1.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-1.5A.25.25 0 0 1 2 6.75v-.5zm0 4a.25.25 0 0 1 .25-.25h.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-.5a.25.25 0 0 1-.25-.25v-.5zm2 0a.25.25 0 0 1 .25-.25h5.5a.25.25 0 0 1 .25.25v.5a.25.25 0 0 1-.25.25h-5.5a.25.25 0 0 1-.25-.25v-.5z">
                                                    </path>
                                                </svg>TIP: Shortcuts
                                            </div>
                                            <p class="mb-4 text-sm text-slate-700 dark:text-slate-400">Navigate the site with ease using keyboard shortcuts.</p>
                                            <div class="flex flex-col text-[13px]">
                                                <div class="flex items-center justify-between border-b border-slate-300 py-2 dark:border-slate-800 transform transition-all opacity-0 -translate-x-3" data-list-translate="-x">
                                                    <div class="text-slate-700 dark:text-slate-400">Open Quick Access</div>
                                                    <div class="flex items-center gap-2 text-[12px]"><kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">Ctrl</kbd>+<kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">Q</kbd></div>
                                                </div>
                                                <div class="flex items-center justify-between border-b border-slate-300 py-2 dark:border-slate-800 transform transition-all opacity-0 -translate-x-3" data-list-translate="-x">
                                                    <div class="text-slate-700 dark:text-slate-400">Close Quick Access</div>
                                                    <div class="flex items-center gap-2 text-[12px]"><kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">Ctrl</kbd>+<kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">Q</kbd><span>or</span><kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">Esc</kbd></div>
                                                </div>
                                                <div class="flex items-center justify-between border-b border-slate-300 py-2 dark:border-slate-800 transform transition-all opacity-0 -translate-x-3" data-list-translate="-x">
                                                    <div class="text-slate-700 dark:text-slate-400">Open Quick Search</div>
                                                    <div class="flex items-center gap-2 text-[12px]"><kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">Ctrl</kbd>+<kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">F</kbd></div>
                                                </div>
                                                <div class="flex items-center justify-between border-b border-slate-300 py-2 dark:border-slate-800 transform transition-all opacity-0 -translate-x-3" data-list-translate="-x">
                                                    <div class="text-slate-700 dark:text-slate-400">Toggle Dark Mode</div>
                                                    <div class="flex items-center gap-2 text-[12px]"><kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">Ctrl</kbd>+<kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">D</kbd></div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="modal-search" class="fixed z-20 w-full h-full top-0 left-0 hidden items-start justify-center p-4 sm:p-6 md:p-20" role="dialog" aria-modal="true">
        <div class="modal-overlay absolute inset-0 dark:bg-slate-950/60 bg-slate-900/30 backdrop-blur-sm transition-opacity opacity-0"></div>
        <div class="modal-container max-w-full w-[42rem] relative inset-0 overflow-y-auto transform transition-all duration-300 opacity-0 -translate-y-4">
            <div>
                <div class="mx-auto animate-popup-in divide-y divide-gray-500 divide-opacity-10 overflow-hidden rounded-md bg-white dark:bg-slate-800 shadow-2x border dark:border-gray-700 border-opacity-70">
                    <div class="relative">
                        <svg class="pointer-events-none absolute top-3 left-4 h-4 w-4 text-gray-900 dark:text-slate-300 text-opacity-40" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                            <path fill-rule="evenodd" d="M9 3.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM2 9a7 7 0 1112.452 4.391l3.328 3.329a.75.75 0 11-1.06 1.06l-3.329-3.328A7 7 0 012 9z" clip-rule="evenodd" />
                        </svg>
                        <input type="text" class="h-10 w-full border-0 bg-transparent pl-11 pr-4 text-gray-900 dark:text-slate-100 placeholder-gray-500 focus:ring-0 text-xs" placeholder="Search...">
                    </div>
                    <div id="result"></div>
                    <div class="py-14 px-6 text-center sm:px-14 hidden animate-popup-in" id="empty">
                        <svg class="mx-auto h-6 w-6 text-gray-900 dark:text-gray-300 text-opacity-40" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
                        </svg>
                        <p class="mt-4 text-xs text-gray-900 dark:text-gray-400">We couldn't find any items with that term. Please try again.</p>
                    </div>
                    <div class="flex justify-between items-center bg-gray-50 dark:bg-slate-900 dark:text-gray-200 py-1.5 px-4 text-xs text-slate-700">
                        <div class="text-[.55rem] px-2 py-[3px] border dark:border-slate-800 rounded"><span class="mr-1 font-semibold">ESC</span><span>TO CLOSE</span></div>
                        <div class=" animate-fade-in" id="indicator-loading">
                            <div class="items-center flex">
                                <span class="relative h-2 w-2 mr-1">
                                    <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400/70 opacity-75"></span>
                                </span>
                                loading...
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script defer src="{!! asset('assets/alpine.min.js') !!}"></script>
    @vite('resources/js/app.js')
    @include('layouts.toast')
    @stack('js')
    <script>
        document.addEventListener('alpine:init', () => {
            Alpine.store('navbarMobile', true);
            Alpine.store('navbarSlide', { open: false, toggle() { this.open = !this.open }})
            let lastScrollTop = 0;
            window.addEventListener('scroll', () => {
                const scrollY = window.scrollY;
                if (scrollY >= lastScrollTop) {
                    lastScrollTop = scrollY;
                    Alpine.store('navbarMobile', false);
                } else if (scrollY <= lastScrollTop) {
                    lastScrollTop = scrollY;
                    Alpine.store('navbarMobile', true);
                }
                if (scrollY + window.innerHeight >= document.body.offsetHeight) {
                    Alpine.store('navbarMobile', false);
                }
            })
        })
    </script>
</body>

</html>
