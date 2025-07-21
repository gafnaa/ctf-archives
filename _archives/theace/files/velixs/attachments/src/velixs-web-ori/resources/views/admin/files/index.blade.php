@extends('layouts.admin.main')

@section('title', 'Files Manager')

@section('content')
    <iframe src="{{ route('admin.files.fortinymce','type=shadow') }}" frameborder="0" style="width: 100%; height: 600px;"></iframe>
@endsection
