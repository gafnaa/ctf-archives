@extends('layouts.dash.main')

@section('content')
<main class="flex-1 dark:text-gray-50 text-gray-900">
    <div class="py-6">
        <div class="mx-auto px-4 sm:px-6 md:px-8">
            <h1 class="text-2xl font-semibold animate-fade-in-left-bounce-3">Hi, Welcome back</h1>

            <main class="flex animate-fade-in-bottom-bounce w-full flex-grow flex-col lg:flex-grow-0 lg:px-12 py-8">
                <div class="flex min-h-full flex-grow flex-col">
                    <h1 class="mb-3 text-15px font-medium text-dark dark:text-light">
                        My Purchase List
                        <span class="ml-1.5 text-gray-600 dark:text-gray-400 text-sm">({{ $purchases->count() }})</span>
                    </h1>

                    @foreach ($purchases->get() as $purchase)
                        @if (!$purchase->_item) @continue @endif
                        <div class="md:flex items-center bg-gray-200/50 dark:bg-gray-800 py-3 px-4 rounded-xl gap-4 sm:gap-5 mb-4">
                            <a href="{!! $purchase->_item->_route() !!}">
                                <div class="relative aspect-w-4 aspect-h-[2.7] bg-gray-300 dark:bg-gray-700 flex-shrink-0 rounded-xl overflow-hidden md:w-36">
                                    <img alt="thumb" class="object-cover" src="{!! $purchase->_item->_image() !!}">
                                </div>
                            </a>
                            <div class="flex flex-1 md:mt-0 mt-3 md:mx-0 mx-1 flex-col gap-3 sm:flex-row sm:items-center sm:justify-between md:gap-0">
                                <div class="text-sm">
                                    @if ($purchase->expires_at)
                                        <p class="text-gray-500 dark:text-gray-300 animate-pulse">Expires on {{ $purchase->_expires_at() }} days</p>
                                    @else
                                        <p class="text-gray-500 dark:text-gray-300">Purchased on {{ $purchase->created_at->format('M d,Y') }}</p>
                                    @endif
                                    <h3 class="my-1 font-medium sm:mb-2">
                                        <a class="transition-colors hover:text-primary-500 line-clamp-2" href="{!! $purchase->_item->_route() !!}">
                                            {{ $purchase->_item->title }}
                                        </a>
                                        <div class="text-gray-600 dark:text-gray-400 mt-1 flex">
                                            Latest Version {{ $purchase->_item->_latestRelease() ?? 'N/A' }}
                                        </div>
                                    </h3>
                                </div>
                                <div class="flex items-center gap-3">
                                    <button data-download="{!! $purchase->id !!}" class="flex disabled:cursor-wait disabled:bg-primary-400 items-center justify-center gap-2 font-semibold w-full min-h-[46px] sm:h-12 rounded-xl py-3 px-4 md:px-5 bg-primary-500 text-white">
                                        <svg fill="none" viewBox="0 0 15 15" xmlns="http://www.w3.org/2000/svg" class="h-auto w-4">
                                            <path d="M7.50014 10.2776C7.35778 10.2776 7.22167 10.2193 7.12376 10.1165L3.47792 6.29709C3.16195 5.96653 3.39667 5.41653 3.85431 5.41653H5.76403V1.42348C5.76403 0.945003 6.15362 0.55542 6.63209 0.55542H8.3682C8.84667 0.55542 9.23626 0.945003 9.23626 1.42348V5.41653H11.146C11.6036 5.41653 11.8383 5.96653 11.5224 6.29709L7.87653 10.1165C7.77862 10.2193 7.64251 10.2776 7.50014 10.2776Z" fill="currentColor"></path>
                                            <path d="M13.1941 13.3334H1.80523C1.26912 13.3334 0.833008 13.0063 0.833008 12.6042V12.3959C0.833008 11.9938 1.26912 11.6667 1.80523 11.6667H13.1941C13.7302 11.6667 14.1663 11.9938 14.1663 12.3959V12.6042C14.1663 13.0063 13.7302 13.3334 13.1941 13.3334Z" fill="currentColor"></path>
                                        </svg>Download
                                    </button>

                                    <div class="relative shrink-0">
                                        <a href="{!! $purchase->_item->_route() !!}" class="flex items-center space-x-[3px] font-semibold p-3 bg-gray-300 dark:bg-gray-700 rounded-xl" type="button">
                                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-6 h-6">
                                                <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 16.875h3.375m0 0h3.375m-3.375 0V13.5m0 3.375v3.375M6 10.5h2.25a2.25 2.25 0 002.25-2.25V6a2.25 2.25 0 00-2.25-2.25H6A2.25 2.25 0 003.75 6v2.25A2.25 2.25 0 006 10.5zm0 9.75h2.25A2.25 2.25 0 0010.5 18v-2.25a2.25 2.25 0 00-2.25-2.25H6a2.25 2.25 0 00-2.25 2.25V18A2.25 2.25 0 006 20.25zm9.75-9.75H18a2.25 2.25 0 002.25-2.25V6A2.25 2.25 0 0018 3.75h-2.25A2.25 2.25 0 0013.5 6v2.25a2.25 2.25 0 002.25 2.25z" />
                                            </svg>
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>

                    @endforeach

                </div>
            </main>

        </div>
    </div>
</main>

<div x-data x-show="$store.modalDownloads.open" class="relative z-50" aria-labelledby="modal-title" role="dialog" aria-modal="true" style="display: none">
    <div x-show="$store.modalDownloads.open" x-transition.opacity  class="fixed inset-0 bg-gray-600/10 backdrop-blur-sm transition-opacity"></div>
    <div class="fixed inset-0 z-20 overflow-y-auto animate-bounce-in" x-show="$store.modalDownloads.open" x-transition:leave="transition ease-in duration-200" x-transition:leave-start="opacity-100" x-transition:leave-end="opacity-0">
        <div class="flex min-h-full items-end justify-center p-4 text-center sm:items-center sm:p-0">
            <div @click.outside="$store.modalDownloads.toggle()" class="relative transform overflow-hidden rounded-3xl bg-white dark:bg-gray-800 px-4 pt-5 pb-4 text-left shadow-xl transition-all sm:my-8 w-full sm:max-w-lg sm:p-6">
                <div class="grid gap-y-3 p-4 text-center" id="content">

                </div>
            </div>
        </div>
    </div>
</div>
@endsection

@push('js')
    <script>
        document.addEventListener('alpine:init', () => { Alpine.store('modalDownloads', { open: false, toggle() { this.open = !this.open }})})

        document.querySelectorAll('[data-download]').forEach(el => {
            el.addEventListener('click', () => {
                el.disabled = true;
                let id = el.dataset.download;
                axios.get('{!! route('dash.getdownload.axio.dp','') !!}'+`/${id}`).then(res => {
                    let release = res.data.release
                    el.disabled = false;
                    if (!release) return toast.toast({
                        style: 'bug',
                        title: 'Version',
                        msg: 'this version is not available',
                    })
                    let html = '';
                    // add button latest version
                    html += `<a target="_blank" href="${release.latest_url}" class="btn-gradient-3 transition-transform duration-300 hover:-translate-y-1 w-full p-3 rounded-full text-gray-50">Latest ${release.latest}</a>`;
                    if(release.archive.length > 0){
                        html += `<div class="relative"><div class="absolute inset-0 flex items-center" aria-hidden="true"><div class="w-full border-t border-gray-300 dark:border-gray-600"></div></div><div class="relative flex justify-center"><span class="bg-white dark:bg-gray-800 px-2 text-sm text-gray-500 dark:text-gray-300">Archive</span></div></div>`;
                    }
                    // add button archive
                    release.archive.forEach(archive => {
                        html += `<a target="_blank" href="${archive.url}" class="bg-gray-600 dark:bg-gray-700 w-full p-3 transition-transform duration-300 hover:-translate-y-1 rounded-full text-gray-50">Version ${archive.version}</a>`;
                    })
                    document.getElementById('content').innerHTML = html;
                    Alpine.store('modalDownloads').toggle()
                }).catch(err => {
                    playN()
                    toast.toast({
                        style: err.response.data.type ?? 'bug',
                        title: err.response.data.title ?? err.response.statusText,
                        msg: err.response.data.message ?? 'Something went wrong',
                    })

                    setTimeout(() => {
                        el.disabled = false;
                    }, 1000);
                })
            })
        })
    </script>
@endpush
