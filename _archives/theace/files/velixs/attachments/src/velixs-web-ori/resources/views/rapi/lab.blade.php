@extends('layouts.landing.main')

@section('content')

@include('rapi.head')


<div class="mx-auto max-w-screen-xl px-4 pb-6 sm:px-6 lg:px-8 lg:pb-16 mt-4">
    <div class="overflow-hidden bg-white dark:bg-slate-900 shadow rounded-xl animate-popup-in">
        <div class="divide-y divide-slate-200 dark:divide-slate-800 lg:grid lg:grid-cols-12 lg:divide-y-0 lg:divide-x">
            <aside class="py-6 lg:col-span-3">
                <nav class="space-y-1" id="tab-ilsya-list">
                    @foreach ($endpoints as $index => $ep)
                        <a href="javascript:void(0)" data-tab="{{$index}}" class="{{ ($index==0)? 'active-endpoint-list' : '' }} border-transparent text-slate-900 dark:text-slate-200 hover:bg-slate-50 hover:dark:bg-slate-800 hover:text-gray-900 group border-l-4 px-3 py-2 flex items-center text-sm font-medium">
                            @switch($ep->method)
                                @case('GET')
                                        <svg xmlns="http://www.w3.org/2000/svg" class="text-slate-400 group-hover:text-slate-500 flex-shrink-0 -ml-1 mr-3 h-6 w-6" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M7 8h-2a2 2 0 0 0 -2 2v4a2 2 0 0 0 2 2h2v-4h-1"></path>
                                            <path d="M14 8h-4v8h4"></path>
                                            <path d="M10 12h2.5"></path>
                                            <path d="M17 8h4"></path>
                                            <path d="M19 8v8"></path>
                                        </svg>
                                    @break
                                @case('POST')
                                        <svg xmlns="http://www.w3.org/2000/svg" class="text-slate-400 group-hover:text-slate-500 flex-shrink-0 -ml-1 mr-3 h-6 w-6" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M3 12h2a2 2 0 1 0 0 -4h-2v8"></path>
                                            <path d="M12 8a2 2 0 0 1 2 2v4a2 2 0 1 1 -4 0v-4a2 2 0 0 1 2 -2z"></path>
                                            <path d="M17 15a1 1 0 0 0 1 1h2a1 1 0 0 0 1 -1v-2a1 1 0 0 0 -1 -1h-2a1 1 0 0 1 -1 -1v-2a1 1 0 0 1 1 -1h2a1 1 0 0 1 1 1"></path>
                                        </svg>
                                    @break
                                @case('PUT')
                                        <svg xmlns="http://www.w3.org/2000/svg" class="text-slate-400 group-hover:text-slate-500 flex-shrink-0 -ml-1 mr-3 h-6 w-6" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M3 12h2a2 2 0 1 0 0 -4h-2v8"></path>
                                            <path d="M17 8h4"></path>
                                            <path d="M19 8v8"></path>
                                            <path d="M10 8v6a2 2 0 1 0 4 0v-6"></path>
                                        </svg>
                                    @break
                                @case('ALL')
                                        <div class="text-slate-400 group-hover:text-slate-500 flex-shrink-0 -ml-1 mr-3 text-xs">
                                            ALL
                                        </div>
                                    @break
                                @default

                            @endswitch
                            <span class="truncate">{{ $ep->title }}</span>
                        </a>
                    @endforeach
                </nav>
            </aside>

            <div class="divide-y divide-gray-200 lg:col-span-9">
                <div class="py-6 px-4 sm:p-6 lg:pb-8">
                    <div id="tab-ilsya-content">
                        @foreach ($endpoints as $index => $ep)
                            <div data-tab="{{ $index }}" class="{{ $index==0 ? '' : 'hidden' }}">
                                <input type="hidden" name="method" value="{{ $ep->method }}">
                                <div class="mb-4 justify-end md:hidden flex">
                                    <button class="btn-endpoint flex items-center h-full rounded-md border-transparent py-1 px-2 text-white bg-primary-500 disabled:bg-primary-400 sm:text-sm">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M21 7l-18 0"></path>
                                            <path d="M18 10l3 -3l-3 -3"></path>
                                            <path d="M6 20l-3 -3l3 -3"></path>
                                            <path d="M3 17l18 0"></path>
                                         </svg>
                                        Test Endpoint
                                    </button>
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-slate-700 dark:text-slate-300">Endpoint</label>
                                    <div class="relative mt-1 rounded-md shadow-sm">
                                        <div class="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                                            <span class="text-gray-500 dark:text-slate-300 text-[10px]">{{ $ep->method }}</span>
                                        </div>
                                        <input type="text" name="url" value="{{ str_replace(["<apikey>"], $auth->api_key ?? '<SIGN UP FOR KEY>', $ep->url) }}" class="block w-full rounded dark:border-0 text-gray-900 dark:text-gray-50 bg-transparent placeholder-gray-500 dark:placeholder-gray-400 border-gray-300 dark:bg-slate-700 pl-12 md:pr-12 text-sm" placeholder="{{ $ep->url }}">
                                        <div class="absolute inset-y-0 right-0 items-center md:flex hidden">
                                            <button class="btn-endpoint flex items-center h-full rounded-md border-transparent py-0 pl-2 pr-2 text-white bg-primary-500 disabled:bg-primary-400 p-3 sm:text-sm">
                                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                    <path d="M21 7l-18 0"></path>
                                                    <path d="M18 10l3 -3l-3 -3"></path>
                                                    <path d="M6 20l-3 -3l3 -3"></path>
                                                    <path d="M3 17l18 0"></path>
                                                 </svg>
                                                Test Endpoint
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                <div class="overflow-hidden rounded-md shadow-2xl mt-10 border dark:border-none">
                                    <div class="bg-slate-100 dark:bg-slate-700 flex items-center py-1 px-3 gap-x-1 justify-between">
                                        <div>
                                            <div class="p-[5px] bg-red-600 inline-block rounded-full"></div>
                                            <div class="p-[5px] bg-yellow-600 inline-block rounded-full"></div>
                                            <div class="p-[5px] bg-green-600 inline-block rounded-full"></div>
                                        </div>
                                        <div class="text-xs text-slate-700 dark:text-slate-300 flex items-center gap-1">
                                            body : { }
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M4 20h4l10.5 -10.5a2.828 2.828 0 1 0 -4 -4l-10.5 10.5v4"></path>
                                                <path d="M13.5 6.5l4 4"></path>
                                            </svg>
                                        </div>
                                        <div></div>
                                    </div>
                                    <div class="editor language-json p-3 text-sm !whitespace-nowrap overflow-x-auto" data-body='{!! $ep->data ?? "{}" !!}'></div>
                                    <input type="hidden" name="data-body" value='{!! $ep->data ?? "{}" !!}'>
                                </div>

                                <div class="overflow-hidden rounded-md shadow-2xl mt-10 border dark:border-none">
                                    <div class="bg-slate-100 dark:bg-slate-700 flex items-center py-1 px-3 gap-x-1 justify-between">
                                        <div>
                                            <div class="p-[5px] bg-red-600 inline-block rounded-full"></div>
                                            <div class="p-[5px] bg-yellow-600 inline-block rounded-full"></div>
                                            <div class="p-[5px] bg-green-600 inline-block rounded-full"></div>
                                        </div>
                                        <div class="text-xs text-slate-700 dark:text-slate-300 flex items-center gap-x-1">
                                            ~response
                                            <span class="response-status-code"><span class="text-green-600">200</span></span>
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M10 10l-6 6v4h4l6 -6m1.99 -1.99l2.504 -2.504a2.828 2.828 0 1 0 -4 -4l-2.5 2.5"></path>
                                                <path d="M13.5 6.5l4 4"></path>
                                                <path d="M3 3l18 18"></path>
                                             </svg>
                                        </div>
                                        <div>
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-slate-700 dark:text-slate-200 cursor-pointer btn-refresh" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M19.933 13.041a8 8 0 1 1 -9.925 -8.788c3.899 -1 7.935 1.007 9.425 4.747"></path>
                                                <path d="M20 4v5h-5"></path>
                                            </svg>
                                        </div>
                                    </div>
                                    <pre class="response-ui language-json p-3 text-sm overflow-auto" data-response='{!! str_replace("<apikey>", $auth->api_key ?? '<SIGN UP FOR KEY>', $ep->response) ?? "{}" !!}'></pre>
                                </div>
                            </div>
                        @endforeach
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
@include('layouts.landing.footer')
@endsection


@push('js')
    <script src="{{ asset('assets/highlight/highlight.min.js?v=1') }}"></script>
    <script>
        const tabIlsyaList = document.getElementById('tab-ilsya-list');
        const tabIlsyaContent = document.getElementById('tab-ilsya-content');

        tabIlsyaList.querySelectorAll('a').forEach((tab) => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();

                tabIlsyaList.querySelectorAll('a').forEach((tab) => {
                    tab.classList.remove('active-endpoint-list');
                });

                tabIlsyaContent.querySelectorAll('div[data-tab]').forEach((tab) => {
                    tab.classList.add('hidden');
                });

                tab.classList.add('active-endpoint-list');
                tabIlsyaContent.querySelector(`div[data-tab="${tab.dataset.tab}"]`).classList.remove('hidden');
            });
        });
    </script>
    <script type="module">
        import { CodeJar } from "{{ asset('assets/codejar.min.js') }}";
        const highlight = (editor) => {
            const parentDiv = editor.closest('[data-tab]');
            parentDiv.querySelector('input[name="data-body"]').value = editor.textContent
            editor.textContent = editor.textContent;
            hljs.highlightBlock(editor);
        };

        const editor = document.querySelectorAll(".editor");
        editor.forEach((e)=>{
            const waduh = new CodeJar(e, highlight);
            let body = e.dataset.body;
            body = body.replace("<apikey>", "{!! $auth->api_key ?? '<SIGN UP FOR KEY>' !!}");
            waduh.updateCode(JSON.stringify(JSON.parse(body), null , 2))
        })
    </script>
    <script src="{{ asset('assets/lab.api.js?v=612312312') }}" type="module"></script>
@endpush

@push('css')
    <link rel="stylesheet" href="{{ asset('assets/highlight/tokyo-night-dark.min.css') }}">
@endpush
