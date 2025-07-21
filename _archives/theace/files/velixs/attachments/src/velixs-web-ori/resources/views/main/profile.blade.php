@extends('layouts.landing.main')

@section('content')
<div class="">
    <div class="relative isolate overflow-hidden mb-10">
        <div class="pt-20 mx-auto lg:max-w-screen-2xl">
            <div class="py-3 lg:px-8 mx-4 lg:mx-0">
                <div class="mb-6 md:mt-24 mt-20">
                    <div class="bg-white px-10 py-5 rounded-lg shadow dark:bg-slate-900">
                        <div class="flex md:justify-between justify-center">
                            <div class="md:flex block md:gap-x-6 gap-x-0 mt-8">
                                <div class="-mt-24 md:ml-3 ml-0 flex justify-center">
                                    @if ($user->role=='admin')
                                        <img class="absolute md:h-32 md:w-32 w-24 h-24 scale-[1.23]" src="{{ asset('assets/img/3fd73db5d33e9b6597e6975eb654e89b89b5db5c.png') }}" alt="border-velixs">
                                    @else
                                        <img class="absolute md:h-32 md:w-32 w-24 h-24 scale-[1.23]" src="{{ asset('assets/img/99e0f27ac1cd7117b342b035d8b725ddb1b76d28.png') }}" alt="border-velixs">
                                    @endif
                                    <img class="md:h-32 md:w-32 w-24 h-24 dark:shadow-blue-500/80 dark:shadow-center rounded" src="{{ $user->_avatar() }}" alt="{{ $user->username }}">
                                </div>
                                <div class="md:-mt-8 mt-5 text-center md:text-start">
                                    <div class="md:text-2xl text-lg font-semibold">
                                        <div class="flex items-center justify-center gap-x-1">
                                            <span class="dark:text-slate-50">{{ $user->name }}</span>
                                            @if ($user->_verified())
                                                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-primary-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                                    <path d="M12.01 2.011a3.2 3.2 0 0 1 2.113 .797l.154 .145l.698 .698a1.2 1.2 0 0 0 .71 .341l.135 .008h1a3.2 3.2 0 0 1 3.195 3.018l.005 .182v1c0 .27 .092 .533 .258 .743l.09 .1l.697 .698a3.2 3.2 0 0 1 .147 4.382l-.145 .154l-.698 .698a1.2 1.2 0 0 0 -.341 .71l-.008 .135v1a3.2 3.2 0 0 1 -3.018 3.195l-.182 .005h-1a1.2 1.2 0 0 0 -.743 .258l-.1 .09l-.698 .697a3.2 3.2 0 0 1 -4.382 .147l-.154 -.145l-.698 -.698a1.2 1.2 0 0 0 -.71 -.341l-.135 -.008h-1a3.2 3.2 0 0 1 -3.195 -3.018l-.005 -.182v-1a1.2 1.2 0 0 0 -.258 -.743l-.09 -.1l-.697 -.698a3.2 3.2 0 0 1 -.147 -4.382l.145 -.154l.698 -.698a1.2 1.2 0 0 0 .341 -.71l.008 -.135v-1l.005 -.182a3.2 3.2 0 0 1 3.013 -3.013l.182 -.005h1a1.2 1.2 0 0 0 .743 -.258l.1 -.09l.698 -.697a3.2 3.2 0 0 1 2.269 -.944zm3.697 7.282a1 1 0 0 0 -1.414 0l-3.293 3.292l-1.293 -1.292l-.094 -.083a1 1 0 0 0 -1.32 1.497l2 2l.094 .083a1 1 0 0 0 1.32 -.083l4 -4l.083 -.094a1 1 0 0 0 -.083 -1.32z" fill="currentColor" stroke-width="0"></path>
                                                </svg>
                                            @endif
                                        </div>
                                    </div>
                                    <div class="md:text-sm text-xs inline-block font-semibold text-slate-500 dark:text-slate-400">{{ "@$user->username" }}</div>
                                </div>
                            </div>
                        </div>

                        @if ($auth && $auth->id == $user->id)
                        <div class="relative mt-5">
                            <div class="absolute inset-0 flex items-center" aria-hidden="true">
                                <div class="w-full border-t border-slate-300 dark:border-slate-800"></div>
                            </div>
                            <div class="relative flex md:justify-start justify-center">
                                <span class="isolate inline-flex -space-x-px rounded-md shadow-sm">
                                    <a href="{{ route('dash.purchases') }}" type="button" class="relative inline-flex items-center rounded-l-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-4 py-2 text-sm font-medium text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M17 8v-3a1 1 0 0 0 -1 -1h-10a2 2 0 0 0 0 4h12a1 1 0 0 1 1 1v3m0 4v3a1 1 0 0 1 -1 1h-12a2 2 0 0 1 -2 -2v-12"></path>
                                            <path d="M20 12v4h-4a2 2 0 0 1 0 -4h4"></path>
                                        </svg>
                                        <span class="text-sm hidden md:block ml-1">Purchases</span>
                                    </a>
                                    <a href="{{ route('dash') }}" type="button" class="relative inline-flex items-center border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-4 py-2 text-sm font-medium text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M4 4m0 2a2 2 0 0 1 2 -2h12a2 2 0 0 1 2 2v12a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2z"></path>
                                            <path d="M10 4l4 16"></path>
                                            <path d="M12 12l-8 2"></path>
                                        </svg>
                                        <span class="text-sm hidden md:block ml-1">Dashboards</span>
                                    </a>
                                    <a href="{{ route('logout') }}" type="button" class="relative inline-flex items-center rounded-r-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-4 py-2 text-sm font-medium text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M14 8v-2a2 2 0 0 0 -2 -2h-7a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2 -2v-2"></path>
                                            <path d="M9 12h12l-3 -3"></path>
                                            <path d="M18 15l3 -3"></path>
                                        </svg>
                                        <span class="text-sm hidden md:block ml-1">Log out</span>
                                    </a>
                                </span>
                            </div>
                        </div>
                        @endif

                    </div>

                    <div class="grid md:grid-cols-12 gap-6 mt-5">
                        <div class="md:col-span-4 bg-white px-10 py-5 rounded-lg shadow dark:bg-slate-900 w-full">
                            <div class="flow-root">
                                <ul role="list" class="-mb-8">
                                    <li>
                                        <div class="relative pb-8">
                                            <span class="absolute top-5 left-5 -ml-px h-full w-0.5 bg-slate-200 dark:bg-slate-700" aria-hidden="true"></span>
                                            <div class="relative flex items-start space-x-3">
                                                <div class="relative">
                                                    <img class="flex h-10 w-10 items-center justify-center rounded-full bg-gray-400 ring-8 ring-white dark:ring-slate-800" src="{{ $user->_avatar() }}" alt="{{ $user->username }}">
                                                </div>
                                                <div class="min-w-0 flex-1">
                                                    <div>
                                                        <div class="text-sm">
                                                            <a href="#" class="font-medium text-slate-900 dark:text-slate-100">{{ $user->name }}</a>
                                                        </div>
                                                        <p class="mt-0.5 text-xs text-gray-500">About</p>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </li>
                                    <li>
                                        <div class="relative pb-8">
                                            <span class="absolute top-5 left-5 -ml-px h-full w-0.5 bg-slate-200 dark:bg-slate-700" aria-hidden="true"></span>
                                            <div class="relative flex items-start space-x-3">
                                                <div>
                                                    <div class="relative px-1">
                                                        <div class="flex h-8 w-8 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-700 ring-8 ring-slate-50/80 dark:ring-slate-800">
                                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-slate-500 dark:text-slate-300" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                                <path d="M18.316 5h-12.632l-3.418 4.019a1.089 1.089 0 0 0 .019 1.447l9.714 10.534l9.715 -10.49a1.09 1.09 0 0 0 .024 -1.444l-3.422 -4.066z"></path>
                                                                <path d="M9 11l3 3l3 -3"></path>
                                                            </svg>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div class="min-w-0 flex-1 py-1.5">
                                                    <div class="text-sm text-gray-500">
                                                        <div class="text-sm text-slate-500 dark:text-slate-400">
                                                            <a href="#" class="font-medium text-slate-900 dark:text-slate-100">Member Since</a>
                                                            {{ $user->created_at->format('M, d Y') }}
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </li>
                                    <li>
                                        <div class="relative pb-8">
                                            <div class="relative flex items-start space-x-3">
                                                <div>
                                                    <div class="relative px-1">
                                                        <div class="flex h-8 w-8 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-700 ring-8 ring-slate-50/80 dark:ring-slate-800">
                                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-slate-500 dark:text-slate-300" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                                <path d="M20 6v12a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2z"></path>
                                                                <path d="M10 16h6"></path>
                                                                <path d="M13 11m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0"></path>
                                                                <path d="M4 8h3"></path>
                                                                <path d="M4 12h3"></path>
                                                                <path d="M4 16h3"></path>
                                                            </svg>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div class="min-w-0 flex-1 py-1.5">
                                                    <div class="text-sm text-slate-500 dark:text-slate-400">
                                                        <a href="#" class="font-medium text-slate-900 dark:text-slate-100">Contacts</a>
                                                        @if ($user->private=='yes')
                                                            Private
                                                        @endif
                                                    </div>
                                                    @if ($user->private!='yes')
                                                    <div class="mt-2 text-sm text-slate-700 dark:text-slate-300">
                                                        <p><span class="font-semibold">Email</span> : {{ $user->email }}</p>
                                                        <p><span class="font-semibold">Whatsap</span> : {{ $user->whatsapp ?? '-' }}</p>
                                                    </div>
                                                    @endif
                                                </div>
                                            </div>
                                        </div>
                                    </li>
                                </ul>
                            </div>
                        </div>
                        <div class="md:col-span-8 bg-white px-6 py-5 rounded-lg shadow dark:bg-slate-900 dark:text-white">
                            <div class="text-sm md:text-base">
                                {{ $user->about ?? 'This profile has not been filled with information about me yet.' }}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

@endsection
