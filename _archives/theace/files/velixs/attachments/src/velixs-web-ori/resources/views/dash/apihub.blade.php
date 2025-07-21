@extends('layouts.dash.main')

@section('content')
<main class="flex-1 dark:text-gray-50 text-gray-900">
    <div class="py-6">
        <div class="mx-auto lg:max-w-screen-xl px-6">
            <main class="flex animate-fade-in-bottom-bounce w-full flex-grow flex-col lg:flex-grow-0 lg:px-12 py-8">
                <div class="flex min-h-full flex-grow flex-col">
                    <h1 class="text-2xl font-bold">API Hub</h1>
                    <nav class="flex gap-x-2 text-sm items-center py-2 mb-5">
                        <div>Dashboard</div>
                        <div class="p-[2px] w-[2px] h-[2px] bg-gray-500 rounded-full"></div>
                        <div class="text-slate-500">API Hub</div>
                    </nav>

                    @if (!$auth->api_key)
                        <div class="bg-white dark:bg-gray-800 w-full border px-5 pb-5 pt-7 dark:border-gray-800 rounded-xl overflow-hidden">
                            <div class="text-center">
                                <div class="lottie h-24" data-json="{{ asset('assets/lottie-json/confetti.json') }}" ></div>
                                <h3 class="mt-2 text-sm font-medium text-gray-900 dark:text-slate-50">Selamat Datang di APIHub</h3>
                                <p class="mt-1 text-sm text-gray-500 dark:text-slate-400">Selangkah lagi anda akan bisa menikmati layanan API Hub dari velixs. <br> Tekan tombol let's go.</p>
                                <div class="mt-6">
                                    <button id="btn-start-apihub" type="button" class="animate-bounce inline-flex items-center rounded-md border border-transparent bg-indigo-600 disabled:bg-indigo-500 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="-ml-1 mr-2 h-5 w-5" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M6 4v16a1 1 0 0 0 1.524 .852l13 -8a1 1 0 0 0 0 -1.704l-13 -8a1 1 0 0 0 -1.524 .852z" stroke-width="0" fill="currentColor"></path>
                                        </svg>
                                        Let's Go!
                                    </button>
                                </div>
                            </div>
                        </div>
                    @else
                        <div class="bg-white dark:bg-slate-800 shadow w-full px-5 pb-5 pt-7 rounded-lg overflow-hidden">
                            <div>
                                <label for="search" class="block text-sm font-medium text-gray-700 dark:text-gray-300">API Key</label>
                                <div class="relative mt-1 flex items-center">
                                    <input type="text" name="apikey" disabled value="{{ $auth->api_key }}" class="block cursor-text w-full rounded-md border-gray-300 dark:border-gray-700 pr-12 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm bg-transparent">
                                    <div class="absolute inset-y-0 right-0 py-1.5 pr-11 md:flex hidden">
                                        <button class="inline-flex items-center hover:bg-primary-500 hover:text-white rounded border border-gray-200 dark:border-gray-600 px-2 font-sans text-sm font-medium text-gray-400">
                                            <svg xmlns="http://www.w3.org/2000/svg" data-clipboard-text="{{ $auth->api_key }}" class="copy-apikey h-4 w-4" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M8 8m0 2a2 2 0 0 1 2 -2h8a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-8a2 2 0 0 1 -2 -2z"></path>
                                                <path d="M16 8v-2a2 2 0 0 0 -2 -2h-8a2 2 0 0 0 -2 2v8a2 2 0 0 0 2 2h2"></path>
                                            </svg>
                                        </button>
                                    </div>
                                    <div class="absolute inset-y-0 right-0 flex py-1.5 pr-1.5">
                                        <button id="btn-regenerate-apikey" class="inline-flex items-center hover:bg-primary-500 hover:text-white rounded border border-gray-200 dark:border-gray-600 px-2 font-sans text-sm font-medium text-gray-400">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M20 11a8.1 8.1 0 0 0 -15.5 -2m-.5 -4v4h4"></path>
                                                <path d="M4 13a8.1 8.1 0 0 0 15.5 2m.5 4v-4h-4"></path>
                                            </svg>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="rounded-lg mt-3 -mb-1 bg-primary-600/90 dark:bg-primary-800 p-2 shadow-lg sm:p-3">
                            <div class="flex flex-wrap items-center justify-between">
                                <div class="flex w-0 flex-1 items-center">
                                    <span class="flex rounded-lg bg-primary-800 dark:bg-primary-600 p-2">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-white" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M12 12c2 -2.96 0 -7 -1 -8c0 3.038 -1.773 4.741 -3 6c-1.226 1.26 -2 3.24 -2 5a6 6 0 1 0 12 0c0 -1.532 -1.056 -3.94 -2 -5c-1.786 3 -2.791 3 -4 2z"></path>
                                        </svg>
                                    </span>
                                    <p class="ml-3 font-medium text-white">
                                        Temukan berbagai API yang tersedia di velixs. ->
                                    </p>
                                </div>
                            </div>
                            <div class="mt-2 w-full flex-shrink-0 sm:order-2 sm:w-auto">
                                <a href="{{ route('rapi') }}" class="flex items-center justify-center rounded-md border border-transparent bg-white px-4 py-2 text-sm font-medium text-indigo-600 shadow-sm hover:bg-indigo-50">Explore API's!</a>
                            </div>
                        </div>

                        <div class="overflow-hidden bg-white dark:bg-slate-800 shadow sm:rounded-lg mt-5">
                            <div class="px-4 py-5 sm:px-6">
                                <h3 class="text-lg font-medium leading-6 text-slate-900 dark:text-slate-100">Plan Information</h3>
                                <p class="mt-1 max-w-2xl text-sm text-slate-500">Your plan information.</p>
                            </div>
                            <div class="border-t border-slate-200 dark:border-slate-700">
                                <dl>
                                    <div class="bg-slate-50 dark:bg-slate-900/30 px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                                        <dt class="text-sm font-medium text-slate-500 dark:text-slate-300">Plan</dt>
                                        <dd class="mt-1 text-sm text-slate-900 dark:text-slate-50 sm:col-span-2 sm:mt-0 uppercase" id="plainfo-plan">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="animate-spin h-4 w-4" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M12 3a9 9 0 1 0 9 9"></path>
                                            </svg>
                                        </dd>
                                    </div>
                                    <div class="bg-white dark:bg-slate-800/90 px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                                        <dt class="text-sm font-medium text-slate-500 dark:text-slate-300">Request / Day</dt>
                                        <dd class="mt-1 text-sm text-slate-900 dark:text-slate-50 sm:col-span-2 sm:mt-0" id="plainfo-max-req">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="animate-spin h-4 w-4" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M12 3a9 9 0 1 0 9 9"></path>
                                            </svg>
                                        </dd>
                                    </div>
                                    <div class="bg-slate-50 dark:bg-slate-900/30 px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                                        <dt class="text-sm font-medium text-slate-500 dark:text-slate-300">Remining Request</dt>
                                        <dd class="mt-1 text-sm text-slate-900 dark:text-slate-50 sm:col-span-2 sm:mt-0" id="plainfo-current-req">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="animate-spin h-4 w-4" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M12 3a9 9 0 1 0 9 9"></path>
                                            </svg>
                                        </dd>
                                    </div>
                                    <div class="bg-white dark:bg-slate-800/90 px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                                        <dt class="text-sm font-medium text-slate-500 dark:text-slate-300">Expired at</dt>
                                        <dd class="mt-1 text-sm text-slate-900 dark:text-slate-50 sm:col-span-2 sm:mt-0" id="plainfo-expired">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="animate-spin h-4 w-4" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M12 3a9 9 0 1 0 9 9"></path>
                                            </svg>
                                        </dd>
                                    </div>
                                </dl>
                            </div>
                        </div>


                    @endif
                </div>
            </main>
        </div>
    </div>
</main>

@endsection

@push('js')
    <script src="{{ asset('assets/lottie.min.js') }}"></script>
    <script src="{!! asset('assets/clipboard.min.js') !!}"></script>
    <script src="{{ asset('assets/highlight/highlight.min.js?v=1') }}"></script>
    <script>
        var clipboard = new ClipboardJS('.copy-apikey');
        clipboard.on('success', function(e) {
            playN()
            toast.toast({
                style: `<svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-sky-400" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M17 3.34a10 10 0 1 1 -14.995 8.984l-.005 -.324l.005 -.324a10 10 0 0 1 14.995 -8.336zm-1.8 10.946a1 1 0 0 0 -1.414 .014a2.5 2.5 0 0 1 -3.572 0a1 1 0 0 0 -1.428 1.4a4.5 4.5 0 0 0 6.428 0a1 1 0 0 0 -.014 -1.414zm-6.19 -5.286l-.127 .007a1 1 0 0 0 .117 1.993l.127 -.007a1 1 0 0 0 -.117 -1.993zm6 0l-.127 .007a1 1 0 0 0 .117 1.993l.127 -.007a1 1 0 0 0 -.117 -1.993z" stroke-width="0" fill="currentColor"></path></svg>`,
                title: 'Copied!',
                msg: 'Apikey copied to clipboard.',
            })
        });
        clipboard.on('error', function(e) {
            console.log(e);
        });

        document.querySelectorAll('.lottie').forEach(el => {
            lottie.loadAnimation({
                container: el,
                renderer: 'svg',
                loop: true,
                autoplay: true,
                path: el.dataset.json
            })
        })

        @if ($auth->api_key)
        document.getElementById('btn-regenerate-apikey').addEventListener('click', () => {
            const btn = document.getElementById('btn-regenerate-apikey');
            btn.disabled = true
            btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 animate-spin" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M20 11a8.1 8.1 0 0 0 -15.5 -2m-.5 -4v4h4"></path><path d="M4 13a8.1 8.1 0 0 0 15.5 2m.5 4v-4h-4"></path></svg>`;
            axios.get('{{ route('dash.apihub.generateapikey.ajax') }}').then((res) => {
                playN()
                toast.toast({
                    style: 'success',
                    title: 'Apikey generated',
                    msg: res.data.message ?? 'Success'
                })
                setTimeout(() => {
                    btn.disabled = false;
                    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M20 11a8.1 8.1 0 0 0 -15.5 -2m-.5 -4v4h4"></path><path d="M4 13a8.1 8.1 0 0 0 15.5 2m.5 4v-4h-4"></path></svg>`;
                }, 1000)
                document.querySelector('input[name="apikey"]').value = res.data.api_key
                document.querySelector('.copy-apikey').setAttribute('data-clipboard-text', res.data.api_key)
            }).catch((err) => {
                playN()
                setTimeout(() => {
                    btn.disabled = false;
                    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M20 11a8.1 8.1 0 0 0 -15.5 -2m-.5 -4v4h4"></path><path d="M4 13a8.1 8.1 0 0 0 15.5 2m.5 4v-4h-4"></path></svg>`;
                },3000)
                toast.toast({
                    style: err.response.data.type ?? 'error',
                    title: err.response.status ?? 'Error',
                    msg: err.response.data.message ?? 'Something went wrong'
                })
            })
        })
        document.addEventListener('DOMContentLoaded', () => {
            axios.get('{{ route('dash.apihub.planinfo.ajax') }}').then((res) => {
                document.getElementById('plainfo-plan').innerHTML = res.data.plan;
                document.getElementById('plainfo-max-req').innerHTML = res.data.max_request;
                document.getElementById('plainfo-current-req').innerHTML = res.data.current_request;
                document.getElementById('plainfo-expired').innerHTML = res.data.expired;
            }).catch((err) => {
                toast.toast({
                    style: 'error',
                    title: err.response.status ?? 'Error',
                    msg: 'Something went wrong, please try again'
                })
            })
        })
        @else
        document.getElementById('btn-start-apihub').addEventListener('click', () => {
            const btn = document.getElementById('btn-start-apihub');
            btn.disabled = true
            btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="animate-spin -ml-1 mr-2 h-5 w-5" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M12 3a9 9 0 1 0 9 9"></path></svg>Let's Go!`;
            axios.get('{{ route('dash.apihub.generateapikey.ajax') }}').then((res) => {
                playN()
                toast.toast({
                    style: 'success',
                    title: 'Apikey updated',
                    msg: res.data.message ?? 'Success'
                })
                setTimeout(() => {
                    // btn.disabled = false;
                    btn.innerHTML = ` <svg xmlns="http://www.w3.org/2000/svg" class="-ml-1 mr-2 h-5 w-5" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M6 4v16a1 1 0 0 0 1.524 .852l13 -8a1 1 0 0 0 0 -1.704l-13 -8a1 1 0 0 0 -1.524 .852z" stroke-width="0" fill="currentColor"></path></svg>Let's Go!`;
                    location.reload()
                },3000)
            }).catch((err) => {
                playN()
                setTimeout(() => {
                    btn.disabled = false;
                    btn.innerHTML = ` <svg xmlns="http://www.w3.org/2000/svg" class="-ml-1 mr-2 h-5 w-5" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M6 4v16a1 1 0 0 0 1.524 .852l13 -8a1 1 0 0 0 0 -1.704l-13 -8a1 1 0 0 0 -1.524 .852z" stroke-width="0" fill="currentColor"></path></svg>Let's Go!`;
                },3000)
                toast.toast({
                    style: err.response.data.type ?? 'error',
                    title: err.response.status ?? 'Error',
                    msg: err.response.data.message ?? 'Something went wrong'
                })
            })
        })
        @endif
    </script>
@endpush
