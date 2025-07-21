@isset($seo->prefix)
<title>{{ $seo->title ? "$seo->title - $ws->meta_title" : $ws->meta_title }}</title>
@else
<title>{{ $seo->title ?? $ws->meta_title }}</title>
@endisset
<meta name='description' itemprop='description' content='{{ $seo->description ?? $ws->meta_description }}'>
<link rel="canonical" href="{{ url()->current() }}">

<meta property="og:title" content="{{ $seo->title ?? $ws->meta_title }}">
<meta property="og:description" content="{{ $seo->description ?? $ws->meta_description }}">
<meta property="og:url" content="{{ url()->current() }}">
<meta property="og:type" content="{{ $seo->type ?? 'website' }}">
<meta property="og:image" content="{{ $seo->image ?? $ws->meta_thumbnail }}">
{{-- <meta property="og:image:width" content="1200">
<meta property="og:image:height" content="627"> --}}

<meta property="twitter:card" content="summary_large_image">
<meta property="twitter:url" content="{{ url()->current() }}">
<meta property="twitter:title" content="{{ $seo->title ?? $ws->meta_title }}">
<meta property="twitter:description" content="{{ $seo->description ?? $ws->meta_description }}">
<meta property="twitter:image" content="{{ $seo->image ?? $ws->meta_thumbnail }}">

{{-- favicon --}}
<!-- Favicon untuk browser -->
<link rel="icon" href="{!! $ws->favicon !!}" type="image/png">
<!-- Favicon untuk iOS (iPhone, iPad) -->
<link rel="apple-touch-icon" sizes="180x180" href="{!! asset('storage/web/favicon/apple-touch-icon.png') !!}">
<!-- Favicon untuk Android -->
<link rel="icon" type="image/png" sizes="192x192" href="{!! asset('storage/web/favicon/android-chrome-192x192.png') !!}">
<link rel="manifest" href="{!! asset('storage/web/favicon/site.webmanifest') !!}">
<!-- Favicon untuk Windows -->
<meta name="msapplication-TileImage" content="{!! asset('storage/web/favicon/msapplication-icon-144x144.png') !!}">
<meta name="msapplication-TileColor" content="#ffffff">

{{-- <meta name="theme-color" content="#ffffff"> --}}


<script type="application/ld+json">{"@context": "https://schema.org","@type": "{{ $seo->type ?? 'website' }}","name": "{{ $seo->title ?? $ws->meta_title }}","url": "{{ url()->current() }}","description": "{{ $seo->description ?? $ws->meta_description }}","image": "{{ $seo->image ?? $ws->meta_thumbnail }}","publisher": {"@type": "Organization","name": "Ilsya"} }</script>
