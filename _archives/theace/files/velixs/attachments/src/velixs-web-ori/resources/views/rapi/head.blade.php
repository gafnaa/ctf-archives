<div class="relative isolate overflow-hidden bg-white dark:bg-slate-950 shadow-sm md:mt-0 mt-10">
    <svg viewBox="0 0 1108 632" aria-hidden="true" class="absolute top-10 left-[calc(69%-30rem)] -z-10 w-[69.25rem] max-w-none transform-gpu blur-3xl sm:left-[calc(50%-18rem)] lg:left-48 lg:top-[calc(50%-30rem)] xl:left-[calc(50%-24rem)]">
        <path fill="url(#175c433f-44f6-4d59-93f0-c5c51ad5566d)" fill-opacity=".2" d="M235.233 402.609 57.541 321.573.83 631.05l234.404-228.441 320.018 145.945c-65.036-115.261-134.286-322.756 109.01-230.655C968.382 433.026 1031 651.247 1092.23 459.36c48.98-153.51-34.51-321.107-82.37-385.717L810.952 324.222 648.261.088 235.233 402.609Z" />
        <defs>
            <linearGradient id="175c433f-44f6-4d59-93f0-c5c51ad5566d" x1="1220.59" x2="-85.053" y1="432.766" y2="638.714" gradientUnits="userSpaceOnUse">
                <stop stop-color="#4F46E5"></stop>
                <stop offset="1" stop-color="#80CAFF"></stop>
            </linearGradient>
        </defs>
    </svg>
    <div class="max-w-7xl px-6 lg:flex lg:gap-x-10 lg:px-8">
        <div class="mx-auto max-w-2xl lg:flex-auto md:mt-20 md:mb-10 my-16">
            <div class="md:flex block items-center text-slate-900 dark:text-white md:text-start text-center">
                <div class="flex md:justify-normal justify-center">
                    <img class="rounded-xl md:mr-4 mr-0 animate-bounce-in" src="{{ $api->_image() }}" alt="{{ $api->title }}" height="65" width="65">
                </div>
                <div class="inline-block">
                    <div class="font-bold md:text-xl text-base mb-1 animate-fade-in-left-bounce">{{ $api->title }}</div>
                    <div class="text-xs text-slate-600 dark:text-slate-400 md:flex block items-center gap-x-1 animate-fade-in-left-bounce-2">
                        By <a class="text-primary-500 font-semibold" href="{{ route('profile',$api->_author->username) }}">{{ $api->_author->name }}</a>
                        <span class="bg-slate-600 dark:bg-slate-400 md:inline-block rounded-full p-[2px] hidden"></span>
                        <div>Updated {{ $api->updated_at->diffForHumans() }}</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div class="border-b border-slate-200 dark:border-slate-900">
            <nav class="-mb-px md:justify-normal justify-center flex space-x-8" aria-label="Tabs">
                <a href="{{ route('rapi.detail',$api->slug) }}" class="{{ Route::is('rapi.detail') ? '!border-indigo-500 !text-indigo-500' : '' }} border-transparent text-slate-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-indigo-500 hover:border-slate-200 dark:hover:border-indigo-300/20 whitespace-nowrap flex py-4 px-1 border-b-2 font-medium text-sm">
                    Readme
                </a>
                <a href="{{ route('rapi.lab',$api->slug) }}" class="{{ Route::is('rapi.lab') ? '!border-indigo-500 !text-indigo-500' : '' }} border-transparent text-slate-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-indigo-500 hover:border-slate-200 dark:hover:border-indigo-300/20 whitespace-nowrap flex py-4 px-1 border-b-2 font-medium text-sm">
                    Lab API
                </a>
                <a href="{{ route('dash.apihub') }}" class="border-transparent text-slate-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-indigo-500 hover:border-slate-200 dark:hover:border-indigo-300/20 whitespace-nowrap flex py-4 px-1 border-b-2 font-medium text-sm">
                    Dashbaords
                </a>
            </nav>
        </div>
    </div>

    <div class="absolute right-[5rem] bottom-0 flex h-8 items-end overflow-hidden md:z-0 -z-10">
        <div class="flex -mb-px h-[2px] w-[29rem] -scale-x-100">
            <div class="w-full flex-none blur-sm [background-image:linear-gradient(90deg,rgba(56,189,248,0)_0%,#0EA5E9_32.29%,rgba(236,72,153,0.3)_67.19%,rgba(236,72,153,0)_100%)]"></div>
            <div class="-ml-[100%] w-full flex-none blur-[1px] [background-image:linear-gradient(90deg,rgba(56,189,248,0)_0%,#0EA5E9_32.29%,rgba(236,72,153,0.3)_67.19%,rgba(236,72,153,0)_100%)]"></div>
        </div>
    </div>
</div>

@if ($auth && !$auth->api_key)
<div class="pt-2 sm:pt-5">
    <div class="mx-auto max-w-7xl px-2 sm:px-6 lg:px-8">
        <div class="rounded-lg bg-primary-600/80 dark:bg-primary-800 p-2 shadow-lg sm:p-3">
            <div class="flex flex-wrap items-center justify-between">
                <div class="flex w-0 flex-1 items-center">
                    <span class="flex rounded-lg bg-primary-800 dark:bg-primary-600 p-2">
                        <svg class="h-6 w-6 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M10.34 15.84c-.688-.06-1.386-.09-2.09-.09H7.5a4.5 4.5 0 110-9h.75c.704 0 1.402-.03 2.09-.09m0 9.18c.253.962.584 1.892.985 2.783.247.55.06 1.21-.463 1.511l-.657.38c-.551.318-1.26.117-1.527-.461a20.845 20.845 0 01-1.44-4.282m3.102.069a18.03 18.03 0 01-.59-4.59c0-1.586.205-3.124.59-4.59m0 9.18a23.848 23.848 0 018.835 2.535M10.34 6.66a23.847 23.847 0 008.835-2.535m0 0A23.74 23.74 0 0018.795 3m.38 1.125a23.91 23.91 0 011.014 5.395m-1.014 8.855c-.118.38-.245.754-.38 1.125m.38-1.125a23.91 23.91 0 001.014-5.395m0-3.46c.495.413.811 1.035.811 1.73 0 .695-.316 1.317-.811 1.73m0-3.46a24.347 24.347 0 010 3.46" />
                        </svg>
                    </span>
                    <p class="ml-3 font-medium text-white">
                        Kamu belum punya apikey.
                    </p>
                </div>
            </div>
            <div class="mt-2 w-full flex-shrink-0 sm:order-2 sm:w-auto">
                <a href="{{ route('dash.apihub') }}" class="flex items-center justify-center rounded-md border border-transparent bg-white px-4 py-2 text-sm font-medium text-indigo-600 shadow-sm hover:bg-indigo-50">Buat API Key !</a>
            </div>
        </div>
    </div>
</div>
@endif
@if (!$auth)
<div class="pt-2 sm:pt-5">
    <div class="mx-auto max-w-7xl px-2 sm:px-6 lg:px-8">
        <div class="rounded-lg bg-primary-600/80 dark:bg-primary-800 p-2 shadow-lg sm:p-3">
            <div class="flex flex-wrap items-center justify-between">
                <div class="flex w-0 flex-1 items-center">
                    <span class="flex rounded-lg bg-primary-800 dark:bg-primary-600 p-2">
                        <svg class="h-6 w-6 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M10.34 15.84c-.688-.06-1.386-.09-2.09-.09H7.5a4.5 4.5 0 110-9h.75c.704 0 1.402-.03 2.09-.09m0 9.18c.253.962.584 1.892.985 2.783.247.55.06 1.21-.463 1.511l-.657.38c-.551.318-1.26.117-1.527-.461a20.845 20.845 0 01-1.44-4.282m3.102.069a18.03 18.03 0 01-.59-4.59c0-1.586.205-3.124.59-4.59m0 9.18a23.848 23.848 0 018.835 2.535M10.34 6.66a23.847 23.847 0 008.835-2.535m0 0A23.74 23.74 0 0018.795 3m.38 1.125a23.91 23.91 0 011.014 5.395m-1.014 8.855c-.118.38-.245.754-.38 1.125m.38-1.125a23.91 23.91 0 001.014-5.395m0-3.46c.495.413.811 1.035.811 1.73 0 .695-.316 1.317-.811 1.73m0-3.46a24.347 24.347 0 010 3.46" />
                        </svg>
                    </span>
                    <p class="ml-3 font-medium text-white">
                        Login atau daftar untuk membuat apikey.
                    </p>
                </div>
            </div>
            <div class="mt-2 w-full flex-shrink-0 sm:order-2 sm:w-auto">
                <a href="{{ route('login') }}" class="flex items-center justify-center rounded-md border border-transparent bg-white px-4 py-2 text-sm font-medium text-indigo-600 shadow-sm hover:bg-indigo-50">Log In!</a>
            </div>
        </div>
    </div>
</div>
@endif

@if ($api->is_published==2)
    <div class="pt-2 sm:pt-5">
        <div class="mx-auto max-w-7xl px-2 sm:px-6 lg:px-8">
            <div class="rounded-lg bg-orange-600/80 dark:bg-orange-800/60 p-2 shadow-lg sm:p-3">
                <div class="flex flex-wrap items-center justify-between">
                    <div class="flex w-0 flex-1 items-center">
                        <span class="flex rounded-lg bg-orange-800 p-2">
                            <svg class="h-6 w-6 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M10.34 15.84c-.688-.06-1.386-.09-2.09-.09H7.5a4.5 4.5 0 110-9h.75c.704 0 1.402-.03 2.09-.09m0 9.18c.253.962.584 1.892.985 2.783.247.55.06 1.21-.463 1.511l-.657.38c-.551.318-1.26.117-1.527-.461a20.845 20.845 0 01-1.44-4.282m3.102.069a18.03 18.03 0 01-.59-4.59c0-1.586.205-3.124.59-4.59m0 9.18a23.848 23.848 0 018.835 2.535M10.34 6.66a23.847 23.847 0 008.835-2.535m0 0A23.74 23.74 0 0018.795 3m.38 1.125a23.91 23.91 0 011.014 5.395m-1.014 8.855c-.118.38-.245.754-.38 1.125m.38-1.125a23.91 23.91 0 001.014-5.395m0-3.46c.495.413.811 1.035.811 1.73 0 .695-.316 1.317-.811 1.73m0-3.46a24.347 24.347 0 010 3.46" />
                            </svg>
                        </span>
                        <p class="ml-3 truncate font-medium text-white">
                            API Maintenance!
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
@elseif ($api->is_published==0)
    <div class="pt-2 sm:pt-5">
        <div class="mx-auto max-w-7xl px-2 sm:px-6 lg:px-8">
            <div class="rounded-lg bg-red-600/80 dark:bg-red-800/60 p-2 shadow-lg sm:p-3">
                <div class="flex flex-wrap items-center justify-between">
                    <div class="flex w-0 flex-1 items-center">
                        <span class="flex rounded-lg bg-red-800 p-2">
                            <svg class="h-6 w-6 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M10.34 15.84c-.688-.06-1.386-.09-2.09-.09H7.5a4.5 4.5 0 110-9h.75c.704 0 1.402-.03 2.09-.09m0 9.18c.253.962.584 1.892.985 2.783.247.55.06 1.21-.463 1.511l-.657.38c-.551.318-1.26.117-1.527-.461a20.845 20.845 0 01-1.44-4.282m3.102.069a18.03 18.03 0 01-.59-4.59c0-1.586.205-3.124.59-4.59m0 9.18a23.848 23.848 0 018.835 2.535M10.34 6.66a23.847 23.847 0 008.835-2.535m0 0A23.74 23.74 0 0018.795 3m.38 1.125a23.91 23.91 0 011.014 5.395m-1.014 8.855c-.118.38-.245.754-.38 1.125m.38-1.125a23.91 23.91 0 001.014-5.395m0-3.46c.495.413.811 1.035.811 1.73 0 .695-.316 1.317-.811 1.73m0-3.46a24.347 24.347 0 010 3.46" />
                            </svg>
                        </span>
                        <p class="ml-3 truncate font-medium text-white">
                            API InActive
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
@endif
