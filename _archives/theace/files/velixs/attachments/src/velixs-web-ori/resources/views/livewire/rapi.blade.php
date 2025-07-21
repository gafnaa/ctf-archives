<div>
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 mt-6 ">
        <div class="block md:flex items-center justify-between space-x-4">
            <div class="flex items-start overflow-hidden lg:max-w-screen-2xl p-1">
                <div class="-mb-7 flex w-full gap-3 overflow-x-auto scroll-smooth pb-7">
                    <button type="button" wire:click='setTags()' class="h-[30px] shrink-0 !rounded-full py-1.5 px-3.5 text-xs font-medium dark:text-white outline-none bg-white hover:bg-gray-100 dark:bg-slate-900 shadow-sm">All</button>
                    @foreach ($tags as $tg)
                        <button wire:click='setTags("{{$tg->slug}}")' type="button" class="h-[30px] shrink-0 !rounded-full py-1.5 px-3.5 text-xs font-medium dark:text-white outline-none bg-white hover:bg-gray-100 dark:bg-slate-900 shadow-sm">{{ $tg->title }}</button>
                    @endforeach
                </div>
            </div>
        </div>
    </div>

    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 mt-6 ">
        <div class="grid grid-cols-1 gap-5 sm:grid-cols-2 gap-y-6 lg:grid-cols-4">
            @foreach ($apis as $lt)
                <div class="relative transform transition-all animate-pulse" wire:loading>
                    <div class="bg-gray-100 dark:bg-gray-800 p-3 rounded-xl overflow-hidden min-h-[9rem]">
                        <div class="flex items-center justify-between">
                            <div class="flex h-8 w-8 lg:w-9 lg:h-9 flex-shrink-0 overflow-hidden mr-2 rounded-md bg-gray-400 dark:bg-gray-700"></div>
                        </div>
                        <div class="mt-4 dark:text-white line-clamp-1 flex items-center gap-x-1">
                            <p class="h-2 w-[80%] bg-gray-400/60 dark:bg-gray-700/60 rounded"></p>
                        </div>
                        <div class="mt-1 text-xs text-slate-600 dark:text-slate-400 line-clamp-3">
                            <p class="h-1.5 mt-3 bg-gray-400/25 dark:bg-gray-700/20 rounded"></p>
                            <p class="h-1.5 mt-3 bg-gray-400/25 dark:bg-gray-700/20 rounded"></p>
                        </div>
                    </div>
                </div>

                <a href="{!! route('rapi.detail',$lt->slug) !!}" class="relative transform transition-all animate-popup-in" wire:loading.remove>
                    <div class="bg-white shadow dark:bg-gray-900 p-3 rounded-xl overflow-hidden min-h-[9rem]">
                        <div class="flex items-center justify-between">
                            <div class="flex h-8 w-8 lg:w-9 lg:h-9 flex-shrink-0 overflow-hidden mr-2 rounded-md shadow-xl">
                                <img alt="{{ $lt->title }}" class="object-cover w-full h-full" src="{{ $lt->_image() }}">
                            </div>
                            <div class="text-base font-medium text-gray-900">
                                <svg xmlns="http://www.w3.org/2000/svg" class="dark:text-slate-500 text-slate-500" width="19" height="19" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M12 17.75l-6.172 3.245l1.179 -6.873l-5 -4.867l6.9 -1l3.086 -6.253l3.086 6.253l6.9 1l-5 4.867l1.179 6.873z"></path>
                                </svg>
                            </div>
                        </div>
                        <div class="mt-2 dark:text-white line-clamp-1 flex items-center gap-x-1">
                            @if ($lt->is_published==2)
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-orange-600" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                <path d="M11.482 20.924a1.666 1.666 0 0 1 -1.157 -1.241a1.724 1.724 0 0 0 -2.573 -1.066c-1.543 .94 -3.31 -.826 -2.37 -2.37a1.724 1.724 0 0 0 -1.065 -2.572c-1.756 -.426 -1.756 -2.924 0 -3.35a1.724 1.724 0 0 0 1.066 -2.573c-.94 -1.543 .826 -3.31 2.37 -2.37c1 .608 2.296 .07 2.572 -1.065c.426 -1.756 2.924 -1.756 3.35 0a1.724 1.724 0 0 0 2.573 1.066c1.543 -.94 3.31 .826 2.37 2.37a1.724 1.724 0 0 0 1.065 2.572c1.312 .318 1.644 1.794 .995 2.697"></path>
                                <path d="M9 12a3 3 0 1 0 6 0a3 3 0 0 0 -6 0"></path>
                                <path d="M20 21l2 -2l-2 -2"></path>
                                <path d="M17 17l-2 2l2 2"></path>
                            </svg>
                            @elseif ($lt->is_published==0)
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-slate-600" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                <path d="M4 13h5"></path>
                                <path d="M12 16v-4m0 -4h3a2 2 0 0 1 2 2v1c0 .554 -.225 1.055 -.589 1.417m-3.411 .583h-1"></path>
                                <path d="M20 8v8"></path>
                                <path d="M9 16v-5.5a2.5 2.5 0 0 0 -5 0v5.5"></path>
                                <path d="M3 3l18 18"></path>
                            </svg>
                            @endif
                            {{ $lt->title }}
                        </div>
                        <div class="mt-1 text-xs text-slate-600 dark:text-slate-400 line-clamp-3">
                            {{ $lt->meta_description }}
                        </div>
                    </div>
                </a>
            @endforeach
        </div>
        {!! $apis->links('layouts.landing.wire-pagination') !!}
    </div>

    <script>
        document.addEventListener('livewire:load', function () {
            Livewire.on('scrollToTop', function () {
                window.scrollTo({
                    top: 0,
                    behavior: 'smooth'
                });
            });
        });
    </script>
</div>
