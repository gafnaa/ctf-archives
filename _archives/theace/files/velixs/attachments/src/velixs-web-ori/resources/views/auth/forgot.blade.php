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

    <div class="flex items-center justify-center min-h-full relative overflow-hidden">
        <div class="text-center mx-auto w-full max-w-sm lg:w-96 px-3">
            <div class="mb-5">
                <h3 class="lg:text-2xl text-xl font-semibold dark:text-gray-50">Reset Your Password</h3>
                <div class="text-gray-500 dark:text-gray-400">Choose a way to perform forgot password</div>
            </div>
            <div x-data="{modal: false}">
                <button @click="modal =! modal" class="w-full mb-4 border dark:border-gray-700 rounded-xl px-3 py-5 flex justify-between animate-bounce-in">
                    <div class="flex items-center">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12 mr-2 text-primary-500" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                            <path d="M3 7a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v10a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-10z"></path>
                            <path d="M3 7l9 6l9 -6"></path>
                        </svg>
                        <div class="text-start">
                            <div class="font-semibold dark:text-gray-50">Using e-mail</div>
                            <div class="text-gray-500 dark:text-gray-400 text-sm">Forgot password using e-mail.</div>
                        </div>
                    </div>
                </button>
                <div x-show="modal" style="display: none;" class="relative z-10" aria-labelledby="modal-title" role="dialog" aria-modal="true">
                    <div x-show="modal" x-transition.opacity class="fixed inset-0 bg-gray-500 bg-opacity-75"></div>
                    <div class="fixed inset-0 z-10 overflow-y-auto">
                        <div class="flex min-h-full justify-center p-4 text-center items-center sm:p-0">
                            <div x-show="modal" @click.outside="modal = false" x-transition="" class="relative animate-bounce-in transform overflow-hidden rounded-lg bg-white dark:bg-gray-800 dark:text-gray-50 px-4 pt-5 pb-4 text-left shadow-xl transition-all sm:my-8 sm:w-full sm:max-w-lg sm:p-6">
                                <div class="absolute top-0 right-0 hidden pt-4 pr-4 sm:block">
                                    <button @click="modal = false" type="button" class="rounded-md text-gray-400 hover:text-gray-500">
                                        <span class="sr-only">Close</span>
                                        <svg class="h-6 w-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
                                        </svg>
                                    </button>
                                </div>
                                <form id="form" action="{{ route('forgot') }}" method="POST">
                                    @csrf
                                    <div class="">
                                        <div class="text-center my-5">
                                            <div class="text-xl">Reset Your Password</div>
                                            <div class="text-sm text-gray-500 dark:text-gray-400">We will send you a link to reset your password</div>
                                        </div>
                                        <div class="my-5">
                                            <label class="block text-sm font-medium text-gray-700 dark:text-gray-100">Email</label>
                                            <div class="mt-1">
                                                <input class="bg-transparent w-full dark:text-gray-100 appearance-none rounded-md border border-gray-300 dark:border-gray-700 px-3 py-3 placeholder-gray-400 dark:placeholder-gray-500 shadow-sm sm:text-sm" placeholder="" name="email" type="email" autocomplete="off" required>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
                                        <button type="submit" class="inline-flex w-full justify-center rounded-md border border-transparent bg-primary-600 px-4 py-2 text-base font-medium text-white shadow-sm hover:bg-primary-700 sm:ml-3 sm:w-auto sm:text-sm">Reset Password</button>
                                        <button @click="modal = false" type="button" class="mt-3 inline-flex w-full justify-center rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-700 dark:text-gray-50 px-4 py-2 text-base font-medium text-gray-700 shadow-sm hover:text-gray-500 sm:mt-0 sm:w-auto sm:text-sm">Cancel</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <a href="{!! $ws->_fogot_whatsapp() !!}" target="_blank" class="w-full mb-4 border dark:border-gray-700 rounded-xl px-3 py-5 flex justify-between animate-bounce-in">
                <div class="flex items-center">
                     <svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12 mr-2 text-primary-500" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                        <path d="M3 21l1.65 -3.8a9 9 0 1 1 3.4 2.9l-5.05 .9"></path>
                        <path d="M9 10a.5 .5 0 0 0 1 0v-1a.5 .5 0 0 0 -1 0v1a5 5 0 0 0 5 5h1a.5 .5 0 0 0 0 -1h-1a.5 .5 0 0 0 0 1"></path>
                     </svg>
                     <div class="text-start">
                        <div class="font-semibold dark:text-gray-50">Using Whatsapp</div>
                        <div class="text-gray-500 dark:text-gray-400 text-sm">Forgot password using whatsapp.</div>
                     </div>
                </div>
            </a>
            <div class="flex justify-center mt-3 animate-fade-in-right-bounce">
                <a class="text-primary-500 font-semibold text-sm flex items-center" href="{!! route('login') !!}">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 mr-1" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                        <path d="M5 12l14 0"></path>
                        <path d="M5 12l6 6"></path>
                        <path d="M5 12l6 -6"></path>
                     </svg>Return to sign in
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
