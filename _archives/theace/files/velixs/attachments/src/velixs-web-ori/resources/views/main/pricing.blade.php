@extends('layouts.landing.main')

@section('content')
<div class="relative overflow-hidden">
    <svg viewBox="0 0 1108 632" aria-hidden="true" class="absolute top-10 left-[calc(50%-4rem)] -z-10 w-[69.25rem] max-w-none transform-gpu blur-3xl sm:left-[calc(50%-18rem)] lg:left-48 lg:top-[calc(50%-30rem)] xl:left-[calc(50%-24rem)]">
        <path fill="url(#175c433f-44f6-4d59-93f0-c5c51ad5566d)" fill-opacity=".2" d="M235.233 402.609 57.541 321.573.83 631.05l234.404-228.441 320.018 145.945c-65.036-115.261-134.286-322.756 109.01-230.655C968.382 433.026 1031 651.247 1092.23 459.36c48.98-153.51-34.51-321.107-82.37-385.717L810.952 324.222 648.261.088 235.233 402.609Z" />
        <defs>
            <linearGradient id="175c433f-44f6-4d59-93f0-c5c51ad5566d" x1="1220.59" x2="-85.053" y1="432.766" y2="638.714" gradientUnits="userSpaceOnUse">
                <stop stop-color="#4F46E5"></stop>
                <stop offset="1" stop-color="#80CAFF"></stop>
            </linearGradient>
        </defs>
    </svg>
    <div class="px-6 lg:px-8 pt-32">
        <div class="text-center">
            <p class="mt-2 text-3xl font-bold tracking-tight sm:text-4xl lg:text-5xl dark:text-slate-50">Pricing</p>
            <p class="mx-auto mt-3 max-w-4xl text-sm sm:mt-5 lg:text-lg dark:text-slate-300">API Hub menyediakan berbagai paket langganan yang dapat disesuaikan dengan kebutuhan bisnis Anda.</p>
        </div>
    </div>

    <div class="mx-auto max-w-7xl py-16 px-6 lg:px-8">
        <div class="space-y-4 sm:grid sm:grid-cols-2 sm:gap-6 sm:space-y-0 lg:mx-auto lg:max-w-4xl xl:mx-0 xl:max-w-none xl:grid-cols-3">
            @foreach ($pricings as $pricing)
                <div class="divide-y divide-slate-200 dark:divide-slate-800 rounded-lg border border-slate-200 dark:border-slate-800 shadow">
                    <div class="p-6">
                        <h2 class="text-lg font-medium leading-6 text-slate-900 dark:text-slate-50 uppercase">{{ $pricing['plan'] ?? '-' }}</h2>
                        <p class="mt-3">
                            @if ($pricing['price']=="0")
                                <span class="text-lg sm:text-xl font-bold tracking-tight text-slate-900 dark:text-slate-50">Lifetime</span>
                            @else
                                <span class="text-lg sm:text-xl font-bold tracking-tight text-slate-900 dark:text-slate-50">Rp {{ number_format($pricing['price'], 0, ',', '.') }}</span>
                                <span class="text-sm sm:text-base font-medium text-gray-500">/ bulan</span>
                            @endif
                        </p>
                        <a href="{{ $pricing['pricing']['button']['url'] ?? '#' }}" class="mt-5 block w-full rounded-md border border-gray-800 bg-slate-800 dark:bg-white py-2 text-center text-sm font-semibold text-white dark:text-black hover:bg-gray-900">{{ $pricing['pricing']['button']['title'] ?? '-' }}</a>
                    </div>
                    <div class="px-6 pt-6 pb-8">
                        <h3 class="text-sm font-medium text-slate-900 dark:text-slate-100">What's included</h3>
                        <ul role="list" class="mt-6 space-y-4">
                            @isset($pricing['pricing']['list'])
                                @foreach ($pricing['pricing']['list'] as $list)
                                    <li class="flex space-x-3">
                                        <svg class="h-5 w-5 flex-shrink-0 text-green-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                            <path fill-rule="evenodd" d="M16.704 4.153a.75.75 0 01.143 1.052l-8 10.5a.75.75 0 01-1.127.075l-4.5-4.5a.75.75 0 011.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 011.05-.143z" clip-rule="evenodd" />
                                        </svg>
                                        <span class="text-sm text-gray-500">{{ $list }}</span>
                                    </li>
                                @endforeach
                            @endif
                        </ul>
                    </div>
                </div>
            @endforeach
        </div>
    </div>
</div>


@endsection
