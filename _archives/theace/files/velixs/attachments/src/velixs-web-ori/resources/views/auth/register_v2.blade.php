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

<body class="dark:bg-gray-900 bg-gray-50 h-full">

    <div class="flex min-h-full relative overflow-hidden">
        <div class="hidden lg:block">
            <svg class="absolute inset-0 -z-10 h-full w-full stroke-gray-200 dark:stroke-white/10 [mask-image:radial-gradient(100%_100%_at_top_right,white,transparent)]" aria-hidden="true">
                <defs>
                    <pattern id="983e3e4c-de6d-4c3f-8d64-b9761d1534cc" width="200" height="200" x="50%" y="-1" patternUnits="userSpaceOnUse">
                        <path d="M.5 200V.5H200" fill="none" />
                    </pattern>
                </defs>
                <svg x="50%" y="-1" class="overflow-visible dark:fill-gray-800/20 fill-white">
                    <path d="M-200 0h201v201h-201Z M600 0h201v201h-201Z M-400 600h201v201h-201Z M200 800h201v201h-201Z" stroke-width="0" />
                </svg>
                <rect width="100%" height="100%" stroke-width="0" fill="url(#983e3e4c-de6d-4c3f-8d64-b9761d1534cc)" />
            </svg>
            <svg viewBox="0 0 1108 632" aria-hidden="true" class="absolute top-10 left-[calc(50%-4rem)] -z-10 w-[69.25rem] max-w-none transform-gpu blur-3xl sm:left-[calc(50%-18rem)] lg:left-48 lg:top-[calc(50%-30rem)] xl:left-[calc(50%-24rem)]">
                <path fill="url(#175c433f-44f6-4d59-93f0-c5c51ad5566d)" fill-opacity=".2" d="M235.233 402.609 57.541 321.573.83 631.05l234.404-228.441 320.018 145.945c-65.036-115.261-134.286-322.756 109.01-230.655C968.382 433.026 1031 651.247 1092.23 459.36c48.98-153.51-34.51-321.107-82.37-385.717L810.952 324.222 648.261.088 235.233 402.609Z" />
                <defs>
                    <linearGradient id="175c433f-44f6-4d59-93f0-c5c51ad5566d" x1="1220.59" x2="-85.053" y1="432.766" y2="638.714" gradientUnits="userSpaceOnUse">
                        <stop stop-color="#4F46E5"></stop>
                        <stop offset="1" stop-color="#80CAFF"></stop>
                    </linearGradient>
                </defs>
            </svg>
        </div>
        <div class="flex bg-white/60 dark:bg-gray-900/50 flex-1 flex-col justify-center py-12 px-4 sm:px-6 lg:flex-none lg:px-20 xl:px-24">
            <div class="mx-auto w-full max-w-sm lg:w-96">
                <div>
                    <img class="h-12 w-auto" src="{!! asset('assets/img/logo.svg') !!}" alt="Your Company">
                    <h2 class="mt-6 text-3xl font-bold tracking-tight text-gray-900 dark:text-white">Get started</h2>
                    <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
                        Already have an account?
                        <a href="{!! route('login') !!}" class="font-medium text-primary-600 hover:text-primary-500">Sign in.</a>
                    </p>
                </div>

                <div class="mt-8">
                    <div>
                        <div class="relative mt-6">
                            <div class="absolute inset-0 flex items-center" aria-hidden="true">
                                <div class="w-full border-t border-gray-300 dark:border-gray-700"></div>
                            </div>
                            <div class="relative flex justify-center text-sm">
                                <span class="bg-white dark:bg-gray-900 px-2 text-gray-500 dark:text-gray-400">sign up</span>
                            </div>
                        </div>
                    </div>

                    <div class="mt-6">
                        <form id="form-register" action="{!! route('register') !!}" method="POST" class="space-y-6">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 dark:text-gray-100">Full Name</label>
                                <div class="mt-1">
                                    <input class="input-versiku" placeholder="Ilsya S" name="fullname" type="text" autocomplete="off" required>
                                </div>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 dark:text-gray-100">Username</label>
                                <div class="mt-1">
                                    <input class="input-versiku" placeholder="ilsya" name="username" type="text" autocomplete="off" required>
                                </div>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 dark:text-gray-100">Email</label>
                                <div class="mt-1">
                                    <input class="input-versiku" placeholder="ilsya@example.com" name="email" type="email" autocomplete="off" required>
                                </div>
                            </div>
                            <div class="flex items-center justify-center">
                                <div class="text-sm dark:text-gray-50">
                                    By signing up, I agree to <a class="text-primary-500 font-semibold" href="{!! route('tos') !!}">Terms of Service</a> and <a class="text-primary-500 font-semibold" href="{!! route('privacy') !!}">Privacy Policy.</a>
                                </div>
                            </div>
                            <div>
                                <button type="submit" class="bg-gray-800 flex items-center justify-center gap-x-2 disabled:bg-gray-700 hover:bg-gray-700 hover:-translate-y-1 duration-300 ease-in-out transition-transform px-2 py-3 rounded-full text-gray-50 w-full">
                                    Create Account
                                </button>
                                <br><br>
                                <a class="text-sm dark:text-slate-200 hover:text-primary-500 flex justify-center items-center" href="{!! route('main') !!}">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-1.5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                        <path d="M5 12l14 0"></path>
                                        <path d="M5 12l4 4"></path>
                                        <path d="M5 12l4 -4"></path>
                                     </svg>
                                    Back to home
                                </a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        <div class="relative hidden min-h-full flex-1 lg:flex items-center justify-center animate-bounce-in">
            <img class="inset-0 object-cover" src="{!! asset('assets/img/illustration_dashboard.png') !!}" alt="">
        </div>
    </div>

    <script defer src="{!! asset('assets/alpine.min.js') !!}"></script>
    @vite('resources/js/app.js')
    @include('layouts.toast')
    <script>
        // regex input username only a-z0-9+
        document.querySelector('input[name="username"]').addEventListener('keyup', function(){
            this.value = encodeURIComponent(this.value.replace(/[^a-z0-9+]/gi, '').toLowerCase());
        })

        document.getElementById('form-register').addEventListener('submit', function(e){
            e.preventDefault();
            button = this.querySelector('button[type="submit"]');
            button.disabled = true;
            button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 animate-spin" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M12 3a9 9 0 1 0 9 9"></path></svg>Create Account';
            var formData = new FormData(this);
            axios.post(this.action, formData,{
                headers: {
                    'Content-Type': 'multipart/form-data',
                    'Accept': 'application/json',
                }
            })
            .then(function(response){
                toast.toast({
                    title: response.status,
                    msg: response.data.message ?? 'Register success',
                    style: 'success',
                });

                setTimeout(() => {
                    window.location.href = '{{ route('register.welcome') }}';
                }, 2000);
            }).catch(function(error){
                button.disabled = false;
                button.innerHTML = 'Create Account'
                playN();
                toast.toast({
                    title: error.response.status,
                    msg: error.response.data.message ?? 'Something went wrong',
                    style: 'error',
                });
                document.getElementById('form-register').querySelector('input[name="password"]').value = '';
            });
        });
    </script>
</body>

</html>
