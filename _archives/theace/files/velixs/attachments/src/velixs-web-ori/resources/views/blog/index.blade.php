@extends('layouts.landing.main')

@section('content')

    @livewire('blog',['sort'=>$sort, 'tags' => $tags])

    @include('layouts.landing.footer')
@endsection

@push('css')
    @livewireStyles
@endpush

@push('js')
    @livewireScripts
@endpush
