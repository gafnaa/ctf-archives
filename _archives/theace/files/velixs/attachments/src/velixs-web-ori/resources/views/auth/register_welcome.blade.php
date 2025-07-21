<!DOCTYPE html>
<html lang="en" data-theme="dark" class="h-full">

<head>
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://rsms.me/inter/inter.css">
    @include('layouts.meta')
    @vite('resources/css/app.css')
    <script>document.querySelector('html').setAttribute('data-theme', localStorage.getItem('theme-ilsya') ?? 'light');</script>
</head>

<body class="dark:bg-gray-900 bg-gray-50 h-full overflow-hidden">

    <div class="flex items-center justify-center min-h-full relative p-3">
        <div class="mx-auto w-full max-w-xl lg:w-100 p-5 border border-dashed rounded-lg border-slate-400 animate-popup-in">
            <div class="mb-5">
                <h3 class="lg:text-2xl text-xl font-semibold dark:text-gray-50 mb-3">😺 Akun Anda berhasil terdaftar.</h3>
                <div class="text-gray-500 dark:text-gray-400"><strong>Silahakn cek email anda {{ $user->email }}.</strong> kami mengirim password dan beberapa informasi yang perlu anda lakukan setelah ini. <br> jika tidak ada tunggu beberapa menit dan coba cek bagian spam.</div>
            </div>
            <div class="flex justify-center mt-3 animate-fade-in-right-bounce">
                <a class="text-primary-500 font-semibold text-sm flex items-center" href="{!! route('login') !!}">
                    Log In
                </a>
            </div>
        </div>
    </div>

    <script defer src="{!! asset('assets/alpine.min.js') !!}"></script>
    @vite('resources/js/app.js')
    @include('layouts.toast')
    <script>
        document.getElementById('form').addEventListener('submit', function(e){
            button = this.querySelector('button[type="submit"]');
            button.disabled = true;
            button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Loading...'
        });
    </script>
</body>

</html>
