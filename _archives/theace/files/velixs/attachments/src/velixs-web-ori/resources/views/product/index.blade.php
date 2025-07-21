@extends('layouts.landing.main')

@section('content')
    @livewire('product',[ 'tags'=> $tags ])
    {{-- <div class="fixed right-4 bottom-4 lg:bottom-[3rem] lg:right-[4rem] z-50">
        <button data-toggle-currency="" class="animate-bounce btn-gradient-3 lg:w-12 lg:h-12 w-11 h-11 ring-1 ring-slate-900/5 dark:ring-slate-200/20 shadow rounded-full flex items-center justify-center">
            <div data-display-currency="USD" class="text-white text-sm font-semibold">USD</div>
            <div data-display-currency="IDR" class="text-white text-sm font-semibold hidden">IDR</div>
        </button>
    </div> --}}
@include('layouts.landing.footer')
@endsection

@push('css')
    @livewireStyles()
@endpush

@push('js')
    @livewireScripts()
@endpush
