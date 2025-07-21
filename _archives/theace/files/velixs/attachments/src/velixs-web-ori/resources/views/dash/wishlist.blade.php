@extends('layouts.dash.main')

@section('content')
<main class="flex-1 dark:text-gray-50 text-gray-900">
    <div class="py-6">
        <div class="mx-auto px-4 sm:px-6 md:px-8">
            <h1 class="text-2xl font-semibold animate-fade-in-left-bounce-3">Hi, Welcome back</h1>

            <main class="flex animate-fade-in-bottom-bounce w-full flex-grow flex-col lg:flex-grow-0 lg:px-12 py-8">
                <div class="flex min-h-full flex-grow flex-col">
                    <h1 class="mb-3 text-15px font-medium text-dark dark:text-light">
                        My My Wishlist
                        <span id="count-wishlist" class="ml-1.5 text-gray-600 dark:text-gray-400 text-sm">()</span>
                    </h1>
                    @foreach ($wishlists->get() as $wishlist)
                    <div class="base md:flex items-center bg-gray-200/50 dark:bg-gray-800 p-4 rounded-xl gap-4 sm:gap-5 mb-4">
                        <a href={!! route('product.detail',$wishlist->slug) !!}">
                            <div class="relative aspect-w-4 aspect-h-[2.7] bg-gray-300 dark:bg-gray-700 flex-shrink-0 rounded-xl overflow-hidden md:w-36">
                                <img alt="thumb" class="object-cover" src="{!! $wishlist->_image() !!}">
                            </div>
                        </a>
                        <div class="flex flex-1 md:mt-0 mt-3 md:mx-0 mx-1 flex-col gap-3 sm:flex-row sm:items-center sm:justify-between md:gap-0">
                            <div class="text-sm">
                                <p class="text-gray-500 dark:text-gray-300">Latest Update {{ $wishlist->updated_at->format('M d, Y') }}</p>
                                <h3 class="my-1 font-medium sm:mb-2">
                                    <a class="transition-colors hover:text-primary-500 line-clamp-2" href="{!! route('product.detail',$wishlist->slug) !!}">
                                        {{ $wishlist->title }}
                                    </a>
                                    <div class="text-gray-600 dark:text-gray-400 mt-2 flex">
                                        @isset($wishlist->price['usd'])
                                        <span data-display-currency="USD" class="rounded-2xl bg-gray-200 dark:bg-gray-700 font-semibold text-green-600 px-1.5 text-[0.7rem]">{{ $wishlist->_display_price('usd') }}</span>
                                        @endisset
                                        @isset($wishlist->price['idr'])
                                        <span data-display-currency="IDR" class="rounded-2xl bg-gray-200 dark:bg-gray-700 font-semibold text-green-600 px-1.5 text-[0.7rem] hidden">{{ $wishlist->_display_price('idr') }}</span>
                                        @endisset
                                    </div>
                                </h3>
                            </div>
                            <div class="flex items-center gap-3">
                                <a href="{!! route('product.detail',$wishlist->slug) !!}" class="flex items-center justify-center gap-2 font-semibold w-full min-h-[46px] sm:h-12 rounded-xl py-3 px-4 md:px-5 bg-primary-500 text-white">
                                     <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                        <path d="M17 7l-10 10"></path>
                                        <path d="M8 7l9 0l0 9"></path>
                                     </svg>DETAIL
                                </a>
                                <div class="relative shrink-0">
                                    <button data-remove-wishlist="{{ $wishlist->slug }}" id="toggle_wishlist" class="flex items-center space-x-[3px] font-semibold p-3 bg-gray-300 dark:bg-gray-700 rounded-xl disabled:cursor-wait" type="button">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-primary-400" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M6.979 3.074a6 6 0 0 1 4.988 1.425l.037 .033l.034 -.03a6 6 0 0 1 4.733 -1.44l.246 .036a6 6 0 0 1 3.364 10.008l-.18 .185l-.048 .041l-7.45 7.379a1 1 0 0 1 -1.313 .082l-.094 -.082l-7.493 -7.422a6 6 0 0 1 3.176 -10.215z" stroke-width="0" fill="currentColor"></path>
                                         </svg>
                                    </button>
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

<div class="fixed bottom-3 right-4 lg:bottom-[3rem] lg:right-[4rem] z-50">
    <button data-toggle-currency="" class="animate-bounce btn-gradient-3 lg:w-12 lg:h-12 w-11 h-11 ring-1 ring-slate-900/5 dark:ring-slate-200/20 shadow rounded-full flex items-center justify-center">
        <div data-display-currency="USD" class="text-white text-sm font-semibold">USD</div>
        <div data-display-currency="IDR" class="text-white text-sm font-semibold hidden">IDR</div>
    </button>
</div>
@endsection

@push('js')
    <script>
        const toggle_wishlist = document.querySelectorAll('[data-remove-wishlist]');
        let count_wishlist = {{ $wishlists->count() }};
        const idcount_wishlist = document.getElementById('count-wishlist');
        idcount_wishlist.innerHTML = '('+count_wishlist+')';
        toggle_wishlist.forEach((item)=>{
            item.addEventListener('click', function(){
                toggle_wishlist.disabled = true;
                item.closest('.base').classList.add('animate-pulse');
                axios.get("{!! route('product.axios.toggle.wishlist', '') !!}/"+item.dataset.removeWishlist).then((res)=>{
                    playN()
                    toast.toast({
                        style: res.data.style ?? 'success',
                        title: res.data.title ?? res.data.status,
                        msg: res.data.message ?? 'Success toggle wishlist.',
                    })
                    setTimeout(() => {
                        item.closest('.base').remove();
                        count_wishlist = (count_wishlist - 1);
                        idcount_wishlist.innerHTML = '('+count_wishlist+')';
                    }, 500);
                }).catch((err)=>{
                    playN()
                    toast.toast({
                        style: err.response.data.style ?? 'error',
                        title: err.response.data.title ?? err.response.statusText,
                        msg: err.response.data.message ?? 'Something went wrong.',
                    })
                    setTimeout(() => {
                        toggle_wishlist.disabled = false;
                    }, 2000);
                })
            })
        })
    </script>
@endpush
