<!DOCTYPE html>
<html lang="en" data-theme="dark">

<head>
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <meta name="base_url" content="{{ url('/') }}">
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://rsms.me/inter/inter.css">
    @include('layouts.meta')
    @vite('resources/css/app.css')
    <script>document.querySelector('html').setAttribute('data-theme', localStorage.getItem('theme-ilsya') ?? 'light');</script>
    @stack('css')
</head>

<body class="dark:bg-gray-900 bg-gray-50 h-full">
    <div>
        <!-- Static sidebar for desktop -->
        <div x-data x-show="$store.nav.open" class="relative z-40 lg:!flex lg:fixed lg:inset-y-0 lg:w-[280px] lg:flex-col" style="display: none;">
            <div x-show="$store.nav.open" x-transition.opacity class="overlay lg:!hidden block fixed inset-0 bg-gray-600 dark:bg-gray-800/40 bg-opacity-75"></div>
            <div x-show="$store.nav.open" @click.outside="$store.nav.toggle()"
            x-transition:leave="transition ease-in duration-300"
            x-transition:leave-start="transform translate-x-0"
            x-transition:leave-end="transform translate-x-[-100%]"
            class="lg:!flex flex-grow h-full flex-col w-[280px] overflow-y-auto scroll-hidden lg:border-r border-dashed border-gray-200 dark:border-gray-800 pt-5 fixed lg:bg-transparent bg-white dark:bg-gray-900">
                <div class="relative">
                    <div class="flex justify-between items-center px-4">
                        <img class="h-8 w-auto" src="{!! asset('assets/img/logo.svg') !!}" alt="Ilsya">
                        <button @click="$store.nav.toggle()" class="text-gray-600 lg:hidden">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                <path d="M5 12l14 0"></path>
                                <path d="M5 12l4 4"></path>
                                <path d="M5 12l4 -4"></path>
                             </svg>
                        </button>
                    </div>
                    <div class="mt-5 flex flex-grow flex-col">
                        <nav class="flex-1 space-y-1 gap-y-1 px-3 pb-4">
                            <a href="{!! route('profile',$auth->username) !!}" class="text-gray-900 group my-2 flex items-center px-4 py-5 text-sm font-medium ilsya-scale-105 rounded-xl bg-gray-200/60 dark:bg-gray-800">
                                <div class="h-11 w-11 rounded-full overflow-hidden mr-2.5">
                                    <img class="object-cover object-center w-full h-full" src="{!! $auth->_avatar() !!}" alt="">
                                </div>
                                <div>
                                    <div class="line-clamp-1 dark:text-white">{{ $auth->name }}</div>
                                    <div class="text-xs text-gray-500 line-clamp-1 dark:text-gray-400">{{ __("Rp  ".number_format($auth->saldo, 2, ',', '.')) }}</div>
                                </div>
                            </a>
                            <div class="py-4 px-3 text-xs font-semibold text-gray-600 dark:text-gray-400">GENERAL</div>
                            <a href="{!! route('dash.purchases') !!}" class="{{ Route::is('dash.purchases') ? 'active-menu-dash' : '' }} text-gray-900 dark:text-gray-300 group flex items-center px-3 py-3 text-sm font-medium rounded-md hover:bg-primary-50 dark:hover:bg-gray-800">
                                <svg xmlns="http://www.w3.org/2000/svg" class="text-gray-500 mr-2 flex-shrink-0 h-6 w-6" viewBox="0 0 24 24" stroke-width="1.6" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M6.331 8h11.339a2 2 0 0 1 1.977 2.304l-1.255 8.152a3 3 0 0 1 -2.966 2.544h-6.852a3 3 0 0 1 -2.965 -2.544l-1.255 -8.152a2 2 0 0 1 1.977 -2.304z"></path>
                                    <path d="M9 11v-5a3 3 0 0 1 6 0v5"></path>
                                </svg>
                                <div>
                                    <div class="line-clamp-1">Purchases</div>
                                    <div class="text-xs text-gray-500 dark:text-gray-400 line-clamp-1">The items you buy are stored here wadwad.</div>
                                </div>
                            </a>
                            <a href="{!! route('dash.wishlist') !!}" class="{{ Route::is('dash.wishlist') ? 'active-menu-dash' : '' }} text-gray-900 dark:text-gray-300 group flex items-center px-3 py-3 text-sm font-medium rounded-md hover:bg-primary-50 dark:hover:bg-gray-800">
                                <svg xmlns="http://www.w3.org/2000/svg" class="text-gray-500 mr-2 flex-shrink-0 h-6 w-6" viewBox="0 0 24 24" stroke-width="1.6" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M19.5 12.572l-7.5 7.428l-7.5 -7.428a5 5 0 1 1 7.5 -6.566a5 5 0 1 1 7.5 6.572"></path>
                                </svg>
                                <div>
                                    <div class="line-clamp-1">My Wishlist</div>
                                </div>
                            </a>
                            @if (config('app.api_velixs_endpoint'))
                            <a href="{!! route('dash.apihub') !!}" class="{{ Route::is('dash.apihub') ? 'active-menu-dash' : '' }} text-gray-900 dark:text-gray-300 group flex items-center px-3 py-3 text-sm font-medium rounded-md hover:bg-primary-50 dark:hover:bg-gray-800">
                                <svg xmlns="http://www.w3.org/2000/svg" class="text-gray-500 mr-2 flex-shrink-0 h-6 w-6" viewBox="0 0 24 24" stroke-width="1.6" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M12 12c2 -2.96 0 -7 -1 -8c0 3.038 -1.773 4.741 -3 6c-1.226 1.26 -2 3.24 -2 5a6 6 0 1 0 12 0c0 -1.532 -1.056 -3.94 -2 -5c-1.786 3 -2.791 3 -4 2z"></path>
                                </svg>
                                <div>
                                    <div class="line-clamp-1">API Hub</div>
                                </div>
                            </a>
                            @endif
                            <a href="{!! route('dash.referral') !!}" class="{{ Route::is('dash.referral') ? 'active-menu-dash' : '' }} text-gray-900 dark:text-gray-300 group flex items-center px-3 py-3 text-sm font-medium rounded-md hover:bg-primary-50 dark:hover:bg-gray-800">
                                <svg xmlns="http://www.w3.org/2000/svg" class="text-gray-500 mr-2 flex-shrink-0 h-6 w-6" viewBox="0 0 24 24" stroke-width="1.6" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M6 5h12l3 5l-8.5 9.5a.7 .7 0 0 1 -1 0l-8.5 -9.5l3 -5"></path>
                                    <path d="M10 12l-2 -2.2l.6 -1"></path>
                                </svg>
                                <div>
                                    <div class="line-clamp-1">Referral <span class="bg-primary-500/80 animate-pulse ml-1 rounded-xl text-white text-[11px] py-[2px] px-2">New</span></div>
                                </div>
                            </a>
                            <div class="py-4 px-3 text-xs font-semibold text-gray-600 dark:text-gray-400">PROFILE</div>
                            <a href="{!! route('dash.personal') !!}" class="{{ Route::is('dash.personal') ? 'active-menu-dash' : '' }} text-gray-900 dark:text-gray-300 group flex items-center px-3 py-3 text-sm font-medium rounded-md hover:bg-primary-50 dark:hover:bg-gray-800">
                                <svg xmlns="http://www.w3.org/2000/svg" class="text-gray-500 mr-2 flex-shrink-0 h-6 w-6" viewBox="0 0 24 24" stroke-width="1.6" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0"></path>
                                    <path d="M12 10m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0"></path>
                                    <path d="M6.168 18.849a4 4 0 0 1 3.832 -2.849h4a4 4 0 0 1 3.834 2.855"></path>
                                </svg>
                                <div>
                                    <div class="line-clamp-1">Personal</div>
                                </div>
                            </a>
                            <a href="{!! route('dash.security') !!}" class="{{ Route::is('dash.security') ? 'active-menu-dash' : '' }} text-gray-900 dark:text-gray-300 group flex items-center px-3 py-3 text-sm font-medium rounded-md hover:bg-primary-50 dark:hover:bg-gray-800">
                                <svg xmlns="http://www.w3.org/2000/svg" class="text-gray-500 mr-2 flex-shrink-0 h-6 w-6" viewBox="0 0 24 24" stroke-width="1.6" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3"></path>
                                    <path d="M12 11m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0"></path>
                                    <path d="M12 12l0 2.5"></path>
                                </svg>
                                <div>
                                    <div class="line-clamp-1">Security & Password</div>
                                </div>
                            </a>
                            <div class="py-4 px-3 text-xs font-semibold text-gray-600 dark:text-gray-400">OTHER</div>
                            <a href="{!! route('main') !!}" class="text-gray-900 dark:text-gray-300 group flex items-center px-3 py-3 text-sm font-medium rounded-md hover:bg-primary-50 dark:hover:bg-gray-800">
                                <svg xmlns="http://www.w3.org/2000/svg" class="text-gray-500 mr-2 flex-shrink-0 h-6 `w-6" viewBox="0 0 24 24" stroke-width="1.6" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M5 12l14 0"></path>
                                    <path d="M5 12l6 6"></path>
                                    <path d="M5 12l6 -6"></path>
                                </svg>
                                <div>
                                    <div class="line-clamp-1">Back Landing</div>
                                </div>
                            </a>
                            <a href="{!! route('logout') !!}" class="text-gray-900 dark:text-gray-300 group flex items-center px-3 py-3 text-sm font-medium rounded-md hover:bg-primary-50 dark:hover:bg-gray-800">
                                <svg xmlns="http://www.w3.org/2000/svg" class="text-gray-500 mr-2 flex-shrink-0 h-6 w-6" viewBox="0 0 24 24" stroke-width="1.6" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M14 8v-2a2 2 0 0 0 -2 -2h-7a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2 -2v-2"></path>
                                    <path d="M9 12h12l-3 -3"></path>
                                    <path d="M18 15l3 -3"></path>
                                </svg>
                                <div>
                                    <div class="line-clamp-1">Logout</div>
                                </div>
                            </a>
                        </nav>
                    </div>
                </div>
            </div>
        </div>

        <div class="flex flex-1 flex-col lg:pl-[280px]">
            <!-- header -->
            <div class="sticky top-0 z-10 flex h-16 bg-gray-50/70 dark:bg-gray-900/60 backdrop-blur flex-shrink-0 px-4 sm:px-6 md:px-8">
                <div class="py-4">
                    <button x-data @click="$store.nav.toggle('open')" type="button" class="text-gray-800 dark:text-gray-300 lg:hidden hover:bg-gray-100 rounded-full p-2">
                        <span class="sr-only">Open Menu</span>
                        <svg class="h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25H12" />
                        </svg>
                    </button>
                </div>
                <div class="flex flex-1 justify-between lg:px-0 px-4">
                    <div class="flex flex-1">
                        <form class="flex w-full md:ml-0" action="#" method="GET">
                            <label for="search-field" class="sr-only">Search</label>
                            <div class="relative w-full text-gray-600 focus-within:text-gray-700">
                                <div class="pointer-events-none absolute inset-y-0 left-0 flex items-center">
                                    <svg class="h-5 w-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                        <path fill-rule="evenodd" d="M9 3.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM2 9a7 7 0 1112.452 4.391l3.328 3.329a.75.75 0 11-1.06 1.06l-3.329-3.328A7 7 0 012 9z" clip-rule="evenodd" />
                                    </svg>
                                </div>
                                <input id="navbarsearchdash" autocomplete="off" class="block bg-transparent h-full w-full border-transparent py-2 pl-8 pr-3 text-gray-900 dark:text-gray-200 placeholder-gray-500 focus:border-transparent focus:placeholder-gray-400 focus:outline-none focus:ring-0 sm:text-sm" placeholder="Search" type="search" name="search">
                            </div>
                        </form>
                    </div>
                    <div class="ml-4 flex items-center md:ml-6">
                        <button data-quick-access="click" type="button" class="p-1 text-gray-400 hover:text-gray-500">
                            <span class="sr-only">Center</span>
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                <path d="M4 4m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z"></path>
                                <path d="M14 4m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z"></path>
                                <path d="M4 14m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z"></path>
                                <path d="M14 17h6m-3 -3v6"></path>
                            </svg>
                        </button>
                    </div>
                </div>
            </div>
            <!-- headedr -->

            @yield('content')

        </div>
    </div>


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
                                        <div class="px-2 text-xl font-bold transform transition-all opacity-0 -translate-y-3 duration-200 ease-in-out" data-list-translate="-y">Recent Activities</div>
                                        <div class="scrollbar-hide flex flex-1 basis-0 flex-col gap-2 overflow-y-auto p-2 pb-4 sm:pb-8">

                                            <div class="transform transition-all opacity-0 -translate-y-3 duration-200 ease-in-out" data-list-translate="-y">
                                                <a class="border-divider-light block rounded-xl border bg-white/60 p-4 text-[13px] dark:border-slate-800 dark:bg-slate-900/60" href="">
                                                    <div class="mb-1 flex justify-between text-xs text-slate-600 dark:text-slate-400">
                                                        <span>REACTION</span><span>8 hours ago</span>
                                                    </div>
                                                    <div class="flex flex-wrap items-baseline gap-x-1">
                                                        <span>the</span>
                                                        <span class="text-accent-600 font-semibold dark:text-accent-400">Tailwind CSS Best Practices</span>
                                                        <span class="lowercase">BLOG POST</span><span>got new</span>
                                                        <span>😲</span>
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
                                                    <div class="flex items-center gap-2 text-[12px]"><kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">Q</kbd></div>
                                                </div>
                                                <div class="flex items-center justify-between border-b border-slate-300 py-2 dark:border-slate-800 transform transition-all opacity-0 -translate-x-3" data-list-translate="-x">
                                                    <div class="text-slate-700 dark:text-slate-400">Close Quick Access</div>
                                                    <div class="flex items-center gap-2 text-[12px]"><kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">Q</kbd><span>or</span><kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">Esc</kbd></div>
                                                </div>
                                                <div class="flex items-center justify-between border-b border-slate-300 py-2 dark:border-slate-800 transform transition-all opacity-0 -translate-x-3" data-list-translate="-x">
                                                    <div class="text-slate-700 dark:text-slate-400">Open Quick Search</div>
                                                    <div class="flex items-center gap-2 text-[12px]"><kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">F</kbd></div>
                                                </div>
                                                <div class="flex items-center justify-between border-b border-slate-300 py-2 dark:border-slate-800 transform transition-all opacity-0 -translate-x-3" data-list-translate="-x">
                                                    <div class="text-slate-700 dark:text-slate-400">Toggle Dark Mode</div>
                                                    <div class="flex items-center gap-2 text-[12px]"><kbd class="rounded-[4px] border border-b-[3px] border-slate-400 bg-slate-300 px-1 py-0.5 font-mono dark:border-slate-300 dark:bg-transparent">D</kbd></div>
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
    <div id="modal-search" class="fixed z-40 w-full h-full top-0 left-0 hidden items-start justify-center p-4 sm:p-6 md:p-20" role="dialog" aria-modal="true">
        <div class="modal-overlay absolute inset-0 dark:bg-slate-950/60 bg-slate-900/30 transition-opacity opacity-0"></div>
        <div class="modal-container max-w-full w-[42rem] relative inset-0 overflow-y-auto transform transition-all duration-300 opacity-0 -translate-y-4">
            <div>
                <div class="mx-auto divide-y divide-gray-500 divide-opacity-10 overflow-hidden rounded-xl bg-white dark:bg-gray-800 shadow-2x border dark:border-gray-700 border-opacity-70">
                    <div class="relative">
                        <!-- Heroicon name: mini/magnifying-glass -->
                        <svg class="pointer-events-none absolute top-3.5 left-4 h-5 w-5 text-gray-900 dark:text-slate-300 text-opacity-40" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                            <path fill-rule="evenodd" d="M9 3.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM2 9a7 7 0 1112.452 4.391l3.328 3.329a.75.75 0 11-1.06 1.06l-3.329-3.328A7 7 0 012 9z" clip-rule="evenodd" />
                        </svg>
                        <input type="text" class="h-12 w-full border-0 bg-transparent pl-11 pr-4 text-gray-900 dark:text-slate-100 placeholder-gray-500 focus:ring-0 sm:text-sm" placeholder="Search...">
                    </div>

                    <!-- Default state, show/hide based on command palette state. -->
                    <div id="result"></div>
                    <div class="py-14 px-6 text-center sm:px-14 hidden animate-popup-in" id="empty">
                        <svg class="mx-auto h-6 w-6 text-gray-900 dark:text-gray-300 text-opacity-40" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
                        </svg>
                        <p class="mt-4 text-sm text-gray-900 dark:text-gray-400">We couldn't find any items with that term. Please try again.</p>
                    </div>
                    <div class="flex flex-wrap items-center bg-gray-50 dark:bg-slate-900 dark:text-gray-200 py-2.5 px-4 text-xs text-gray-700">
                        <div class="mr-auto">
                            Type<span class="mx-1 font-semibold">esc</span><span>to close search.
                        </div>
                        <div class="hidden animate-fade-in" id="indicator-loading">
                            <div class="items-center flex">
                                <span class="relative h-2 w-2 mr-1">
                                    <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400/70 opacity-75"></span>
                                </span>
                                Processing...
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
    <script>document.addEventListener('alpine:init', () => { Alpine.store('nav', { open: false, toggle() { this.open = !this.open }})})</script>
</body>

</html>
