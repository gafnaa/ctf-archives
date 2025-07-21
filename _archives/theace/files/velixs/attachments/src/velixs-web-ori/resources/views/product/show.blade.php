@extends('layouts.landing.main')

@section('content')

<main>
    <div class="relative isolate overflow-hidden">
        <div class="pt-20 mx-auto lg:max-w-screen-2xl">
            <div class="py-3 lg:px-8 mx-4 lg:mx-0">
                <div class="mb-6">
                    <h1 class="mb-4 font-semibold tracking-tight leading-[1.1] text-slate-900 dark:text-white lg:text-3xl text-2xl transition-all animate-fade-in-left-bounce">
                        {{ $item->title }}
                    </h1>
                    <div class="flex justify-between text-gray-500 dark:text-gray-400 text-sm items-center">
                        <div class="animate-fade-in-left-bounce">
                            <div class="flex items-center justify-center mr-3">
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1.5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0"></path>
                                    <path d="M12 12h3.5"></path>
                                    <path d="M12 7v5"></path>
                                </svg> {{ $item->created_at->format('D, d M Y')  }}
                            </div>
                        </div>
                        <div class="animate-fade-in-right-bounce relative flex">
                            <div x-data="{ modal: false }">
                                <!-- modal share start-->
                                <div x-show="modal" x-on:click.away="modal = false" x-transition class="absolute top-10 right-2 z-[902] flex w-56 flex-col overflow-hidden rounded-2xl border bg-white/70 pb-2 pt-1 backdrop-blur dark:border-slate-800 dark:bg-slate-900" style="display: hidden;">
                                    <div class="py-3 px-4 text-center text-[13px] text-lg font-bold" role="none">Share this on</div>
                                    <a href="https://www.facebook.com/sharer/sharer.php?u={!! url()->current() !!}" target="_blank" rel="noreferrer nofollow" class="flex w-full items-center gap-3 px-4 py-2 text-[13px] hover:bg-slate-100 hover:dark:bg-[#1d263a]" role="none">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M12 10.174c1.766 -2.784 3.315 -4.174 4.648 -4.174c2 0 3.263 2.213 4 5.217c.704 2.869 .5 6.783 -2 6.783c-1.114 0 -2.648 -1.565 -4.148 -3.652a27.627 27.627 0 0 1 -2.5 -4.174z"></path>
                                            <path d="M12 10.174c-1.766 -2.784 -3.315 -4.174 -4.648 -4.174c-2 0 -3.263 2.213 -4 5.217c-.704 2.869 -.5 6.783 2 6.783c1.114 0 2.648 -1.565 4.148 -3.652c1 -1.391 1.833 -2.783 2.5 -4.174z"></path>
                                         </svg>
                                        <span class="flex items-center gap-2" role="none">
                                            Facebook
                                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="h-3 w-3" role="none">
                                                <path fill-rule="evenodd" d="M4.25 5.5a.75.75 0 00-.75.75v8.5c0 .414.336.75.75.75h8.5a.75.75 0 00.75-.75v-4a.75.75 0 011.5 0v4A2.25 2.25 0 0112.75 17h-8.5A2.25 2.25 0 012 14.75v-8.5A2.25 2.25 0 014.25 4h5a.75.75 0 010 1.5h-5z" clip-rule="evenodd" role="none"></path>
                                                <path fill-rule="evenodd" d="M6.194 12.753a.75.75 0 001.06.053L16.5 4.44v2.81a.75.75 0 001.5 0v-4.5a.75.75 0 00-.75-.75h-4.5a.75.75 0 000 1.5h2.553l-9.056 8.194a.75.75 0 00-.053 1.06z" clip-rule="evenodd" role="none"></path>
                                            </svg>
                                        </span>
                                    </a>
                                    <a href="https://twitter.com/intent/tweet?via=ilsya&amp;url={!! url()->current() !!}" target="_blank" rel="noreferrer nofollow" class="flex w-full items-center gap-3 px-4 py-2 text-[13px] hover:bg-slate-100 hover:dark:bg-[#1d263a]" role="none">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M4 4l11.733 16h4.267l-11.733 -16z"></path>
                                            <path d="M4 20l6.768 -6.768m2.46 -2.46l6.772 -6.772"></path>
                                        </svg>
                                        <span class="flex items-center gap-2" role="none">
                                            Twitter
                                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="h-3 w-3" role="none">
                                                <path fill-rule="evenodd" d="M4.25 5.5a.75.75 0 00-.75.75v8.5c0 .414.336.75.75.75h8.5a.75.75 0 00.75-.75v-4a.75.75 0 011.5 0v4A2.25 2.25 0 0112.75 17h-8.5A2.25 2.25 0 012 14.75v-8.5A2.25 2.25 0 014.25 4h5a.75.75 0 010 1.5h-5z" clip-rule="evenodd" role="none"></path>
                                                <path fill-rule="evenodd" d="M6.194 12.753a.75.75 0 001.06.053L16.5 4.44v2.81a.75.75 0 001.5 0v-4.5a.75.75 0 00-.75-.75h-4.5a.75.75 0 000 1.5h2.553l-9.056 8.194a.75.75 0 00-.053 1.06z" clip-rule="evenodd" role="none"></path>
                                            </svg>
                                        </span>
                                    </a>
                                    <a href="https://www.linkedin.com/sharing/share-offsite/?url={!! url()->current() !!}" target="_blank" rel="noreferrer nofollow" class="flex w-full items-center gap-3 px-4 py-2 text-[13px] hover:bg-slate-100 hover:dark:bg-[#1d263a]" role="none">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M4 4m0 2a2 2 0 0 1 2 -2h12a2 2 0 0 1 2 2v12a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2z"></path>
                                            <path d="M8 11l0 5"></path>
                                            <path d="M8 8l0 .01"></path>
                                            <path d="M12 16l0 -5"></path>
                                            <path d="M16 16v-3a2 2 0 0 0 -4 0"></path>
                                         </svg>
                                        <span class="flex items-center gap-2" role="none">
                                            Linkedin
                                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="h-3 w-3" role="none">
                                                <path fill-rule="evenodd" d="M4.25 5.5a.75.75 0 00-.75.75v8.5c0 .414.336.75.75.75h8.5a.75.75 0 00.75-.75v-4a.75.75 0 011.5 0v4A2.25 2.25 0 0112.75 17h-8.5A2.25 2.25 0 012 14.75v-8.5A2.25 2.25 0 014.25 4h5a.75.75 0 010 1.5h-5z" clip-rule="evenodd" role="none"></path>
                                                <path fill-rule="evenodd" d="M6.194 12.753a.75.75 0 001.06.053L16.5 4.44v2.81a.75.75 0 001.5 0v-4.5a.75.75 0 00-.75-.75h-4.5a.75.75 0 000 1.5h2.553l-9.056 8.194a.75.75 0 00-.053 1.06z" clip-rule="evenodd" role="none"></path>
                                            </svg>
                                        </span>
                                    </a>
                                    <a href="whatsapp://send?text={!! url()->current() !!}" target="_blank" rel="noreferrer nofollow" class="flex w-full items-center gap-3 px-4 py-2 text-[13px] hover:bg-slate-100 hover:dark:bg-[#1d263a]" role="none">
                                         <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M3 21l1.65 -3.8a9 9 0 1 1 3.4 2.9l-5.05 .9"></path>
                                            <path d="M9 10a.5 .5 0 0 0 1 0v-1a.5 .5 0 0 0 -1 0v1a5 5 0 0 0 5 5h1a.5 .5 0 0 0 0 -1h-1a.5 .5 0 0 0 0 1"></path>
                                         </svg>
                                        <span class="flex items-center gap-2" role="none">
                                            Whatsapp
                                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="h-3 w-3" role="none">
                                                <path fill-rule="evenodd" d="M4.25 5.5a.75.75 0 00-.75.75v8.5c0 .414.336.75.75.75h8.5a.75.75 0 00.75-.75v-4a.75.75 0 011.5 0v4A2.25 2.25 0 0112.75 17h-8.5A2.25 2.25 0 012 14.75v-8.5A2.25 2.25 0 014.25 4h5a.75.75 0 010 1.5h-5z" clip-rule="evenodd" role="none"></path>
                                                <path fill-rule="evenodd" d="M6.194 12.753a.75.75 0 001.06.053L16.5 4.44v2.81a.75.75 0 001.5 0v-4.5a.75.75 0 00-.75-.75h-4.5a.75.75 0 000 1.5h2.553l-9.056 8.194a.75.75 0 00-.053 1.06z" clip-rule="evenodd" role="none"></path>
                                            </svg>
                                        </span>
                                    </a>
                                    <div class="border-t dark:border-slate-800" role="none"></div>
                                    <button @click="modal =! modal" type="button" data-clipboard-text="{!! url()->current() !!}" class="copy-link flex w-full items-center gap-3 px-4 py-2 text-[13px] hover:bg-slate-100 hover:dark:bg-[#1d263a]" role="none">
                                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="h-4 w-4" role="none">
                                            <path fill-rule="evenodd" d="M18.97 3.659a2.25 2.25 0 00-3.182 0l-10.94 10.94a3.75 3.75 0 105.304 5.303l7.693-7.693a.75.75 0 011.06 1.06l-7.693 7.693a5.25 5.25 0 11-7.424-7.424l10.939-10.94a3.75 3.75 0 115.303 5.304L9.097 18.835l-.008.008-.007.007-.002.002-.003.002A2.25 2.25 0 015.91 15.66l7.81-7.81a.75.75 0 011.061 1.06l-7.81 7.81a.75.75 0 001.054 1.068L18.97 6.84a2.25 2.25 0 000-3.182z" clip-rule="evenodd" role="none"></path>
                                        </svg>Copy link
                                    </button>
                                    <button @click="modal =! modal" type="button" data-clipboard-text="{!! url()->current() !!}{{ auth()->check() ? '?ref=' . auth()->user()->username : '' }}" class="copy-link flex w-full items-center gap-3 px-4 py-2 text-[13px] hover:bg-slate-100 hover:dark:bg-[#1d263a]" role="none">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                            <path d="M9 15l6 -6"></path>
                                            <path d="M11 6l.463 -.536a5 5 0 0 1 7.071 7.072l-.534 .464"></path>
                                            <path d="M13 18l-.397 .534a5.068 5.068 0 0 1 -7.127 0a4.972 4.972 0 0 1 0 -7.071l.524 -.463"></path>
                                        </svg>Copy link with Referral
                                    </button>
                                </div>
                                <!-- modal share end -->

                                <button @click="modal =! modal" class="flex items-center justify-center mr-3">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1.5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                        <path d="M6 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0"></path>
                                        <path d="M18 6m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0"></path>
                                        <path d="M18 18m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0"></path>
                                        <path d="M8.7 10.7l6.6 -3.4"></path>
                                        <path d="M8.7 13.3l6.6 3.4"></path>
                                    </svg><span class="hidden md:block">Share</span>
                                </button>
                            </div>
                            <button id="toggle_wishlist" class="disabled:cursor-wait">
                                @if ($item->_hasWishlist($auth))
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-primary-400" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M6.979 3.074a6 6 0 0 1 4.988 1.425l.037 .033l.034 -.03a6 6 0 0 1 4.733 -1.44l.246 .036a6 6 0 0 1 3.364 10.008l-.18 .185l-.048 .041l-7.45 7.379a1 1 0 0 1 -1.313 .082l-.094 -.082l-7.493 -7.422a6 6 0 0 1 3.176 -10.215z" stroke-width="0" fill="currentColor"></path>
                                 </svg>
                                @else
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M19.5 12.572l-7.5 7.428l-7.5 -7.428a5 5 0 1 1 7.5 -6.566a5 5 0 1 1 7.5 6.572"></path>
                                </svg>
                                @endif
                            </button>
                        </div>
                    </div>
                </div>

                <div class="lg:grid grid-cols-12 gap-6">

                    <div class="col-span-8 mb-5">
                        <div class="bg-gray-100 dark:bg-slate-800 w-100 rounded-lg overflow-hidden aspect-w-4 aspect-h-[2.6] shadow-sm animate-bounce-in">
                            <img class="object-cover object-center w-full h-full" src="{!! $item->_image() !!}" alt="">
                        </div>
                        <div class="lg:px-0 px-2 py-10">
                            <div class="lg:p-10 rounded-xl overflow-hidden">
                                <article class="prose max-w-none dark:prose-invert prose-img:rounded-xl prose-pre:m-0 prose-pre:rounded-none">{!! $item->content !!}</article>
                            </div>
                        </div>
                    </div>
                    <div class="col-span-4">
                        <div class="lg:sticky lg:top-20">
                            <div class="bg-white text-sm dark:bg-gray-900 shadow w-100 p-5 rounded-xl mb-3 dark:text-gray-200 text-gray-800 animate-fade-in-left-bounce-2">
                                <div class="w-100 p-5 rounded-xl mb-5 btn-gradient animate-idleY">
                                    @if ($item->github)
                                        <h1 class="text-2xl font-bold text-white mb-3">GitHub</h1>
                                    @else
                                        <div class="mb-3 flex items-center gap-x-2">
                                            @isset($item->price['usd'])
                                                <h1 data-display-currency="USD" class="text-2xl font-bold text-white animate-popup-in">{!! $item->_display_price('usd') !!}</h1>
                                            @endisset
                                            @isset($item->price['idr'])
                                                <h1 data-display-currency="IDR" class="text-2xl font-bold text-white hidden animate-popup-in">{!! $item->_display_price('idr') !!}</h1>
                                            @endisset
                                            <div data-toggle-currency="" class="p-[3px] rounded bg-white text-primary-500 cursor-pointer">
                                                <svg xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5" viewBox="0 0 24 24" stroke-width="2.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                    <path d="M4 12v-3a3 3 0 0 1 3 -3h13m-3 -3l3 3l-3 3"></path>
                                                    <path d="M20 12v3a3 3 0 0 1 -3 3h-13m3 3l-3 -3l3 -3"></path>
                                                </svg>
                                            </div>
                                        </div>
                                    @endif
                                    <div class="flex">
                                        @if ($item->github)
                                            <a href="{!! $item->github !!}" target="_blank" class="bg-white dark:bg-slate-600 dark:hover:bg-slate-700 text-violet-500 dark:text-white font-bold rounded-xl py-2 px-3 w-full mr-2 flex items-center justify-center">
                                                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1.5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                    <path d="M9 19c-4.3 1.4 -4.3 -2.5 -6 -3m12 5v-3.5c0 -1 .1 -1.4 -.5 -2c2.8 -.3 5.5 -1.4 5.5 -6a4.6 4.6 0 0 0 -1.3 -3.2a4.2 4.2 0 0 0 -.1 -3.2s-1.1 -.3 -3.5 1.3a12.3 12.3 0 0 0 -6.2 0c-2.4 -1.6 -3.5 -1.3 -3.5 -1.3a4.2 4.2 0 0 0 -.1 3.2a4.6 4.6 0 0 0 -1.3 3.2c0 4.6 2.7 5.7 5.5 6c-.6 .6 -.6 1.2 -.5 2v3.5"></path>
                                                 </svg>Git Repository
                                            </a>
                                        @else
                                            @if ($item->_hasOwned($auth))
                                                <a href="{!! route('dash.purchases') !!}" class="bg-white dark:bg-slate-600 dark:hover:bg-slate-700 text-violet-500 dark:text-white font-bold rounded-xl py-2 px-3 w-full mr-2 flex items-center justify-center">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1.5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M13 19h-8a2 2 0 0 1 -2 -2v-11a2 2 0 0 1 2 -2h4l3 3h7a2 2 0 0 1 2 2v3.5"></path>
                                                        <path d="M19 16l-2 3h4l-2 3"></path>
                                                    </svg>My Library
                                                </a>
                                            @else
                                                @if ($item->_isFree())
                                                    <button class="bg-white jsclick-claim-license dark:bg-slate-600 dark:hover:bg-slate-700 text-violet-500 dark:text-white font-bold rounded-xl py-2 px-3 w-full mr-2 flex items-center justify-center">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1.5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                            <path d="M12 19h-7a2 2 0 0 1 -2 -2v-11a2 2 0 0 1 2 -2h4l3 3h7a2 2 0 0 1 2 2v3.5"></path>
                                                            <path d="M16 19h6"></path>
                                                            <path d="M19 16v6"></path>
                                                        </svg> Add Library
                                                    </button>
                                                @else
                                                    <a target="_blank" href="{!! $ws->_payment_whatsapp(url()->current()) !!}" class="bg-white dark:bg-slate-600 dark:hover:bg-slate-700 text-violet-500 dark:text-white font-bold rounded-xl py-2 px-3 w-full mr-2 flex items-center justify-center">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1.5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                            <path d="M6 19m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0"></path>
                                                            <path d="M17 19m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0"></path>
                                                            <path d="M17 17h-11v-14h-2"></path>
                                                            <path d="M6 5l14 1l-1 7h-13"></path>
                                                        </svg>BUY NOW
                                                    </a>
                                                @endif
                                            @endif
                                        @endif
                                        <a href="{!! $item->preview !!}" target="_blank" class="bg-white dark:bg-slate-600 dark:hover:bg-slate-700 text-violet-500 dark:text-white rounded-xl py-3 px-3">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 " viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M17 7l-10 10"></path>
                                                <path d="M8 7l9 0l0 9"></path>
                                            </svg>
                                        </a>
                                    </div>
                                </div>
                                <div class="flex items-center mb-3">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="mr-2" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                        <path d="M4 7a2 2 0 0 1 2 -2h12a2 2 0 0 1 2 2v12a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-12z"></path>
                                        <path d="M16 3v4"></path>
                                        <path d="M8 3v4"></path>
                                        <path d="M4 11h16"></path>
                                        <path d="M11 15h1"></path>
                                        <path d="M12 15v3"></path>
                                    </svg>Published on {{ $item->created_at->format('d M Y') }}
                                </div>
                                <div class="flex items-center mb-3">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="mr-2" width="22" height="22" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                        <path d="M18.918 8.174c2.56 4.982 .501 11.656 -5.38 12.626c-7.702 1.687 -12.84 -7.716 -7.054 -13.229c.309 -.305 1.161 -1.095 1.516 -1.349c0 .528 .27 3.475 1 3.167c3 0 4 -4.222 3.587 -7.389c2.7 1.411 4.987 3.376 6.331 6.174z"></path>
                                    </svg>Updated on {{ $item->updated_at->format('d M Y') }}
                                </div>
                                <div class="flex items-center mb-3">
                                    <svg viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg" class="mr-2" width="22" height="22">
                                        <path d="M14.2521 12.7481C13.0145 12.7481 12.0077 13.755 12.0077 14.9925C12.0077 16.2301 13.0145 17.2369 14.2521 17.2369C15.4896 17.2369 16.4965 16.2301 16.4965 14.9925C16.4965 13.755 15.4896 12.7481 14.2521 12.7481ZM14.2521 15.8903C13.757 15.8903 13.3543 15.4876 13.3543 14.9925C13.3543 14.4974 13.757 14.0948 14.2521 14.0948C14.7472 14.0948 15.1498 14.4974 15.1498 14.9925C15.1498 15.4876 14.7472 15.8903 14.2521 15.8903Z" fill="currentColor"></path>
                                        <path d="M17.8569 4.07381C17.7294 3.91064 17.5339 3.81548 17.3268 3.81548H4.1562L3.5502 1.27999C3.47771 0.977014 3.2068 0.763123 2.89527 0.763123H0.673316C0.301431 0.763087 0 1.06452 0 1.4364C0 1.80829 0.301431 2.10972 0.673316 2.10972H2.36381L4.55209 11.266C4.62459 11.5692 4.8955 11.7828 5.20702 11.7828H15.6884C15.9979 11.7828 16.2677 11.5719 16.3419 11.2716L17.9804 4.65058C18.03 4.44952 17.9844 4.23697 17.8569 4.07381ZM15.1616 10.4362H5.73848L4.47802 5.16211H16.4665L15.1616 10.4362Z" fill="currentColor"></path>
                                        <path d="M6.10511 12.7481C4.86753 12.7481 3.86072 13.755 3.86072 14.9925C3.86072 16.2301 4.86756 17.2369 6.10511 17.2369C7.34265 17.2369 8.34949 16.2301 8.34949 14.9925C8.34949 13.755 7.34265 12.7481 6.10511 12.7481ZM6.10511 15.8903C5.61 15.8903 5.20735 15.4876 5.20735 14.9925C5.20735 14.4974 5.61 14.0948 6.10511 14.0948C6.60021 14.0948 7.00286 14.4974 7.00286 14.9925C7.00286 15.4876 6.60021 15.8903 6.10511 15.8903Z" fill="currentColor"></path>
                                    </svg>Sales {{ $sales }}
                                </div>
                                <div>
                                    <div class="flex items-center mb-3">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="mr-2" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M7.859 6h-2.834a2.025 2.025 0 0 0 -2.025 2.025v2.834c0 .537 .213 1.052 .593 1.432l6.116 6.116a2.025 2.025 0 0 0 2.864 0l2.834 -2.834a2.025 2.025 0 0 0 0 -2.864l-6.117 -6.116a2.025 2.025 0 0 0 -1.431 -.593z"></path>
                                            <path d="M17.573 18.407l2.834 -2.834a2.025 2.025 0 0 0 0 -2.864l-7.117 -7.116"></path>
                                            <path d="M6 9h-.01"></path>
                                        </svg> Fill in
                                    </div>
                                    <div class="flex flex-wrap">
                                        @foreach ($item->_tags() as $tg)
                                            <a href="{!! route('product',['tags'=> $tg->slug]) !!}" class="badge-fillin mb-2 mr-1.5" href="">{{ $tg->title }}</a>
                                        @endforeach
                                    </div>
                                </div>
                            </div>
                            <div class="bg-white text-sm dark:bg-gray-900 shadow w-100 p-5 rounded-xl mb-3 dark:text-gray-200 text-gray-800 animate-fade-in-left-bounce-3">
                                <div class="flex justify-between items-center">
                                    <div class="flex items-center">
                                        <div class="h-14 w-14 rounded-full overflow-hidden">
                                            <img class="object-cover object-center" src="{!! $item->_author->_avatar() !!}" alt="">
                                        </div>
                                        <div class="ml-2">
                                            <div class="font-bold">{{ $item->_author->name }}</div>
                                            <div class="text-[12px]">~ Author</div>
                                        </div>
                                    </div>
                                    <div>
                                        <a href="{!! route('profile',$item->_author->username) !!}" class="dark:text-white">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                <path d="M5 12l14 0"></path>
                                                <path d="M15 16l4 -4"></path>
                                                <path d="M15 8l4 4"></path>
                                            </svg>
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    </div>


    <!-- mobile footer buy -->
    <div x-data>
        <div x-bind:class="$store.navbarMobile ? 'duration-300 translate-y-0' : 'duration-500 translate-y-24'" class="fixed w-full bottom-0 lg:hidden block bg-white dark:bg-gray-900 shadow rounded p-3 transition-transform transform animate-footer-product">
            <div class="flex justify-center -mt-1">
                <div @click="$store.navbarMobile = !$store.navbarMobile" class="cursor-pointer animate-pulse bg-gray-300 dark:bg-gray-600 py-[0.140rem] px-5 rounded-full"></div>
            </div>
            <div class="mt-3 px-3">
                <div class="flex items-center mb-3 gap-x-2">
                    @if ($item->github)
                        <h1 class="text-2xl font-bold dark:text-white text-gray-700">GitHub</h1>
                    @else
                        @isset($item->price['usd'])
                            <h1 data-display-currency="USD" class="text-2xl font-bold dark:text-white text-gray-700 ">{!! $item->_display_price('usd') !!}</h1>
                        @endisset
                        @isset($item->price['idr'])
                            <h1 data-display-currency="IDR" class="text-2xl font-bold dark:text-white text-gray-700 hidden">{!! $item->_display_price('idr') !!}</h1>
                        @endisset
                        <div data-toggle-currency="" class="p-[3px] rounded bg-primary-500 text-white">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                <path d="M4 12v-3a3 3 0 0 1 3 -3h13m-3 -3l3 3l-3 3"></path>
                                <path d="M20 12v3a3 3 0 0 1 -3 3h-13m3 3l-3 -3l3 -3"></path>
                            </svg>
                        </div>
                    @endif
                </div>
                <div class="flex">
                    <a href="{!! $item->preview !!}" class="bg-gray-200 dark:bg-slate-600 dark:hover:bg-slate-700 text-gray-700 dark:text-white rounded-xl p-3 mr-2">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                            <path d="M17 7l-10 10"></path>
                            <path d="M8 7l9 0l0 9"></path>
                        </svg>
                    </a>
                    @if ($item->github)
                    <a href="{!! $item->github !!}" target="_blank" class="btn-gradient text-white rounded-xl font-semibold py-2 px-3 w-full flex items-center justify-center">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1.5" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                            <path d="M9 19c-4.3 1.4 -4.3 -2.5 -6 -3m12 5v-3.5c0 -1 .1 -1.4 -.5 -2c2.8 -.3 5.5 -1.4 5.5 -6a4.6 4.6 0 0 0 -1.3 -3.2a4.2 4.2 0 0 0 -.1 -3.2s-1.1 -.3 -3.5 1.3a12.3 12.3 0 0 0 -6.2 0c-2.4 -1.6 -3.5 -1.3 -3.5 -1.3a4.2 4.2 0 0 0 -.1 3.2a4.6 4.6 0 0 0 -1.3 3.2c0 4.6 2.7 5.7 5.5 6c-.6 .6 -.6 1.2 -.5 2v3.5"></path>
                         </svg> Git Repository
                    </a>
                    @else
                        @if ($item->_hasOwned($auth))
                        <a href="{!! route('dash.purchases') !!}" class="btn-gradient text-white rounded-xl font-semibold py-2 px-3 w-full flex items-center justify-center">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1.5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                <path d="M13 19h-8a2 2 0 0 1 -2 -2v-11a2 2 0 0 1 2 -2h4l3 3h7a2 2 0 0 1 2 2v3.5"></path>
                                <path d="M19 16l-2 3h4l-2 3"></path>
                            </svg> My Library
                        </a>
                        @else
                            @if ($item->_isFree())
                            <button class="btn-gradient jsclick-claim-license text-white rounded-xl font-semibold py-2 px-3 w-full flex items-center justify-center">
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1.5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M12 19h-7a2 2 0 0 1 -2 -2v-11a2 2 0 0 1 2 -2h4l3 3h7a2 2 0 0 1 2 2v3.5"></path>
                                    <path d="M16 19h6"></path>
                                    <path d="M19 16v6"></path>
                                </svg> Add Library
                            </button>
                            @else
                            <a target="_blank" href="{!! $ws->_payment_whatsapp(url()->current()) !!}" class="btn-gradient text-white rounded-xl font-semibold py-2 px-3 w-full flex items-center justify-center">
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1.5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M6 19m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0"></path>
                                    <path d="M17 19m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0"></path>
                                    <path d="M17 17h-11v-14h-2"></path>
                                    <path d="M6 5l14 1l-1 7h-13"></path>
                                </svg> Buy Now!
                            </a>
                            @endif
                        @endif
                    @endif
                </div>
            </div>
        </div>
    </div>

</main>
@include('layouts.landing.footer')
@endsection

@push('js')
    <script src="{!! asset('assets/clipboard.min.js') !!}"></script>
    <script>
        var clipboard = new ClipboardJS('.copy-link');
        clipboard.on('success', function(e) {
            toast.toast({
                style: `<svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-sky-400" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M17 3.34a10 10 0 1 1 -14.995 8.984l-.005 -.324l.005 -.324a10 10 0 0 1 14.995 -8.336zm-1.8 10.946a1 1 0 0 0 -1.414 .014a2.5 2.5 0 0 1 -3.572 0a1 1 0 0 0 -1.428 1.4a4.5 4.5 0 0 0 6.428 0a1 1 0 0 0 -.014 -1.414zm-6.19 -5.286l-.127 .007a1 1 0 0 0 .117 1.993l.127 -.007a1 1 0 0 0 -.117 -1.993zm6 0l-.127 .007a1 1 0 0 0 .117 1.993l.127 -.007a1 1 0 0 0 -.117 -1.993z" stroke-width="0" fill="currentColor"></path></svg>`,
                title: 'Link Copied.',
                msg: 'Link copied to clipboard. You can paste it anywhere now.',
            })
        });

        const toggle_wishlist = document.getElementById('toggle_wishlist');
        toggle_wishlist.addEventListener('click', function(){
            toggle_wishlist.disabled = true;
            axios.get("{!! route('product.axios.toggle.wishlist', $item->slug) !!}").then((res)=>{
                playN()
                toast.toast({
                    style: res.data.style ?? 'success',
                    title: res.data.title ?? res.data.status,
                    msg: res.data.message ?? 'Success toggle wishlist.',
                })
                if(res.data.wishlist=='added'){
                    toggle_wishlist.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-primary-400" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M6.979 3.074a6 6 0 0 1 4.988 1.425l.037 .033l.034 -.03a6 6 0 0 1 4.733 -1.44l.246 .036a6 6 0 0 1 3.364 10.008l-.18 .185l-.048 .041l-7.45 7.379a1 1 0 0 1 -1.313 .082l-.094 -.082l-7.493 -7.422a6 6 0 0 1 3.176 -10.215z" stroke-width="0" fill="currentColor"></path></svg>`;
                } else {
                    toggle_wishlist.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M19.5 12.572l-7.5 7.428l-7.5 -7.428a5 5 0 1 1 7.5 -6.566a5 5 0 1 1 7.5 6.572"></path></svg>`;
                }
                setTimeout(() => {
                    toggle_wishlist.disabled = false;
                }, 2000);
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

        document.querySelectorAll('.jsclick-claim-license').forEach((el)=>{
            el.addEventListener('click', function(els){
                els.target.disabled = true;
                els.target.innerHTML = 'Loading...'
                axios.get("{!! route('product.claim_library.axios', $item->slug) !!}").then((res)=>{
                    playN()
                    toast.toast({
                        style: res.data.style ?? 'info',
                        title: res.data.title ?? res.data.status,
                        msg: res.data.message ?? 'Success claim free.',
                    })
                    setTimeout(() => {
                        window.location.href = "{!! route('dash.purchases') !!}";
                    }, 2000);
                }).catch((err)=>{
                    playN()
                    toast.toast({
                        style: err.response.data.style ?? 'error',
                        title: err.response.data.title ?? err.response.statusText,
                        msg: err.response.data.message ?? 'Something went wrong.',
                    })
                    setTimeout(() => {
                        els.target.disabled = false;
                        els.target.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1.5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M12 19h-7a2 2 0 0 1 -2 -2v-11a2 2 0 0 1 2 -2h4l3 3h7a2 2 0 0 1 2 2v3.5"></path><path d="M16 19h6"></path><path d="M19 16v6"></path></svg> Add Library'
                    }, 1000);
                })
            })
        })
    </script>
@endpush
