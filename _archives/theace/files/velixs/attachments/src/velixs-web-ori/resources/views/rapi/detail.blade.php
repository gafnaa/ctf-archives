@extends('layouts.landing.main')

@section('content')

@include('rapi.head')

<section class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 mt-6">
    <div class="animate-popup-in">
        <article class="prose dark:prose-invert prose-img:rounded-xl max-w-full md:prose-base prose-sm prose-pre:p-0 prose-pre:m-0 prose-pre:bg-transparent prose-pre:rounded-none">{!! $api->readme !!}</article>
    </div>
</section>
@include('layouts.landing.footer')
@endsection


@push('js')
    <script src="{{ asset('assets/highlight/highlight.min.js?v=1') }}"></script>
    <script>
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
