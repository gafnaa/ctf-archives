<div>

    <main class="mt-5 lg:mt-0">

        <div class="mx-auto max-w-2xl py-16 px-4 sm:py-24 sm:px-6 lg:max-w-screen-2xl lg:px-8">
            <div class="block md:flex items-center justify-between space-x-4">
                <div class="flex items-start overflow-hidden lg:max-w-screen-2xl">
                    <div class="-mb-7 flex w-full gap-3 overflow-x-auto scroll-smooth pb-7">
                        <button wire:click='setTags()' class="h-[30px] shrink-0 !rounded-full border py-1.5 px-3.5 text-xs font-medium outline-none bg-gray-100 hover:bg-gray-200 dark:bg-slate-900 dark:border-slate-800 dark:text-gray-200 dark:hover:bg-slate-900/50">All</button>
                        @foreach ($product_tags as $ptag)
                            <button wire:click='setTags("{{$ptag->slug}}")' class="h-[30px] shrink-0 !rounded-full border py-1.5 px-3.5 text-xs font-medium outline-none bg-gray-100 hover:bg-gray-200 dark:bg-slate-900 dark:border-slate-800 dark:text-gray-200 dark:hover:bg-slate-900/50">{{ $ptag->title }}</button>
                        @endforeach
                    </div>
                </div>
            </div>

            <div class="mt-6 grid grid-cols-1 gap-5 sm:grid-cols-2 gap-y-6 lg:grid-cols-4">

                @foreach ($products as $product)
                    <div class="group relative animate-pulse" wire:loading>
                        <div class="bg-white dark:bg-gray-900 p-2 rounded-xl overflow-hidden">
                            <div class="aspect-w-4 aspect-h-[2.7] overflow-hidden rounded-lg bg-gray-300 dark:bg-gray-700"></div>
                            <div class="flex items-center mt-4">
                                <div class="flex h-8 w-8 lg:w-9 lg:h-9 flex-shrink-0 bg-gray-300 dark:bg-gray-700 overflow-hidden mr-2 rounded-full"></div>
                                <div class="block w-full">
                                    <div class="line-clamp-1 text-sm dark:text-gray-100" href="#">
                                        <span aria-hidden="true" class="absolute inset-0"></span>
                                        <div class="h-2 bg-gray-300 dark:bg-gray-700 rounded"></div>
                                    </div>
                                    <div class="grid grid-cols-3 gap-4 mt-3">
                                        <div class="h-2 bg-gray-300 dark:bg-gray-700 rounded col-span-2"></div>
                                        <div class="h-2 bg-gray-300 dark:bg-gray-700 rounded col-span-1"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="group relative transform transition-all animate-popup-in" wire:loading.remove>
                        <div class="bg-white shadow-sm dark:bg-gray-900 p-2 rounded-xl overflow-hidden">
                            <div class="aspect-w-4 aspect-h-[2.6] overflow-hidden rounded-lg bg-gray-300 dark:bg-gray-700">
                                <a href="{!! route('product.detail',$product->slug) !!}">
                                    <img src="{!! $product->_image() !!}" alt="thumb" class="object-cover object-center w-full h-full hover:scale-105 duration-500 ease-in-out transition-transform">
                                </a>
                            </div>
                            <div class="flex items-center mt-4">
                                <div class="flex h-8 w-8 lg:w-9 lg:h-9 flex-shrink-0 overflow-hidden mr-2">
                                    <img alt="{{ $product->_author->name }}" class="rounded-full object-cover w-full h-full" src="{!! $product->_author->_avatar() !!}">
                                </div>
                                <div class="block w-full">
                                    <a class="line-clamp-1 font-semibold text-sm text-gray-800 dark:text-gray-100" href="{!! route('product.detail',$product->slug) !!}">
                                        {{ $product->title }}
                                    </a>
                                    <div class="flex items-center justify-between text-base font-medium text-gray-900">
                                        <a href="{!! route('profile',$product->_author->username) !!}" class="text-xs text-gray-500">{{ $product->_author->name }}</a>
                                        @isset($product->price['usd'])
                                            <span data-toggle-currency="" data-display-currency="USD" class="rounded-2xl cursor-pointer bg-gray-200/40 dark:bg-gray-800 font-semibold text-green-600 px-2 text-[0.7rem]">{!! $product->_display_price('usd') !!}</span>
                                        @endisset
                                        @isset($product->price['idr'])
                                            <span data-toggle-currency="" data-display-currency="IDR" class="rounded-2xl cursor-pointer bg-gray-200/40 dark:bg-gray-800 font-semibold text-green-600 px-2 text-[0.7rem] hidden">{!! $product->_display_price('idr') !!}</span>
                                        @endisset
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                @endforeach

            </div>

            {!! $products->links('layouts.landing.wire-pagination') !!}

        </div>

    </main>
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
