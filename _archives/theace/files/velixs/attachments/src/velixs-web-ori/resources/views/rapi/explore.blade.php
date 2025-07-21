@extends('layouts.landing.main')

@section('content')
<div class="relative isolate overflow-hidden bg-white dark:bg-slate-950 shadow-sm">
    <svg viewBox="0 0 1108 632" aria-hidden="true" class="absolute top-10 left-[calc(-74%-47rem)] -z-10 w-[69.25rem] max-w-none transform-gpu blur-3xl sm:left-[calc(50%-18rem)] lg:left-48 lg:top-[calc(50%-30rem)] xl:left-[calc(50%-24rem)]">
        <path fill="url(#175c433f-44f6-4d59-93f0-c5c51ad5566d)" fill-opacity=".2" d="M235.233 402.609 57.541 321.573.83 631.05l234.404-228.441 320.018 145.945c-65.036-115.261-134.286-322.756 109.01-230.655C968.382 433.026 1031 651.247 1092.23 459.36c48.98-153.51-34.51-321.107-82.37-385.717L810.952 324.222 648.261.088 235.233 402.609Z" />
        <defs>
            <linearGradient id="175c433f-44f6-4d59-93f0-c5c51ad5566d" x1="1220.59" x2="-85.053" y1="432.766" y2="638.714" gradientUnits="userSpaceOnUse">
                <stop stop-color="#4F46E5"></stop>
                <stop offset="1" stop-color="#80CAFF"></stop>
            </linearGradient>
        </defs>
    </svg>
    <div class="max-w-7xl px-6 lg:flex lg:gap-x-10 lg:px-8">
        <div class="mx-auto max-w-2xl lg:flex-auto lg:my-20 mb-10 mt-24">
            <h1 class="mt-10 animate-fade-in-left-bounce text-4xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-5xl">
                Explore <span class="bg-slate-50 dark:bg-slate-800/40 inline-block md:-rotate-3 -rotate-3 md:mt-0 mt-3 shadow py-1 px-3 rounded-xl"><span class="text-transparent bg-clip-text bg-gradient-to-r from-sky-500 to-violet-600"> API Hub</span></span>
            </h1>
            <p class="mt-6 leading-8 animate-fade-in-left-bounce-2 text-slate-600 dark:text-slate-300">
                Browse Public <span class="text-slate-800 dark:text-slate-300 font-semibold">Rest APIs</span> in the Velixs API Hub - API directory. <span class="text-slate-800 dark:text-slate-300 font-semibold">Register today Free!</span>
            </p>
        </div>
    </div>
    <div class="absolute left-[5rem] bottom-0 flex h-8 items-end overflow-hidden">
        <div class="flex -mb-px h-[2px] w-[29rem] -scale-x-100">
            <div class="w-full flex-none blur-sm [background-image:linear-gradient(90deg,rgba(56,189,248,0)_0%,#0EA5E9_32.29%,rgba(236,72,153,0.3)_67.19%,rgba(236,72,153,0)_100%)]"></div>
            <div class="-ml-[100%] w-full flex-none blur-[1px] [background-image:linear-gradient(90deg,rgba(56,189,248,0)_0%,#0EA5E9_32.29%,rgba(236,72,153,0.3)_67.19%,rgba(236,72,153,0)_100%)]"></div>
        </div>
    </div>
</div>
@livewire('rapi', ['tag'=> $tag, 'sort'=> $sort, 'collection'=> $collection])

@include('layouts.landing.footer')
@endsection

@push('css')
    @livewireStyles
@endpush

@push('js')
    @livewireScripts
@endpush
