@extends('layouts.dash.main')

@section('content')
<div class="bg-gradient-to-b relative">
    <div class="grid grid-cols-12 max-w-screen-2xl mx-auto mt-40">
        <section class="col-span-10 col-start-2">
            <div class="relative">
                <div class="flex w-full flex-col justify-center gap-4 lg:gap-8 md:flex-row">
                    <div class="w-full lg:w-1/2">
                        <div class="flex flex-col items-center h-full gap-x-6 text-center lg:flex-row lg:items-start lg:text-left">
                            <div class="flex-shrink-0">
                                <img src="{{ $auth->_avatar() }}" alt="{{ $auth->username }}" class="h-14 w-14 rounded-full lg:h-16 lg:w-16">
                            </div>
                            <div class="flex flex-col h-full">
                                <div class="flex-1">
                                    <h1 class=" mt-1.5 flex items-center justify-center font-semibold dark:text-gray-100 sm:text-lg lg:mt-0 lg:justify-start lg:text-2xl">{{ $auth->name }}
                                        @if ($auth->_verified())
                                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="mt-0.5 ml-2 inline h-5 w-5 text-primary-600 dark:text-white">
                                                <path d="M12.01 2.011a3.2 3.2 0 0 1 2.113 .797l.154 .145l.698 .698a1.2 1.2 0 0 0 .71 .341l.135 .008h1a3.2 3.2 0 0 1 3.195 3.018l.005 .182v1c0 .27 .092 .533 .258 .743l.09 .1l.697 .698a3.2 3.2 0 0 1 .147 4.382l-.145 .154l-.698 .698a1.2 1.2 0 0 0 -.341 .71l-.008 .135v1a3.2 3.2 0 0 1 -3.018 3.195l-.182 .005h-1a1.2 1.2 0 0 0 -.743 .258l-.1 .09l-.698 .697a3.2 3.2 0 0 1 -4.382 .147l-.154 -.145l-.698 -.698a1.2 1.2 0 0 0 -.71 -.341l-.135 -.008h-1a3.2 3.2 0 0 1 -3.195 -3.018l-.005 -.182v-1a1.2 1.2 0 0 0 -.258 -.743l-.09 -.1l-.697 -.698a3.2 3.2 0 0 1 -.147 -4.382l.145 -.154l.698 -.698a1.2 1.2 0 0 0 .341 -.71l.008 -.135v-1l.005 -.182a3.2 3.2 0 0 1 3.013 -3.013l.182 -.005h1a1.2 1.2 0 0 0 .743 -.258l.1 -.09l.698 -.697a3.2 3.2 0 0 1 2.269 -.944zm3.697 7.282a1 1 0 0 0 -1.414 0l-3.293 3.292l-1.293 -1.292l-.094 -.083a1 1 0 0 0 -1.32 1.497l2 2l.094 .083a1 1 0 0 0 1.32 -.083l4 -4l.083 -.094a1 1 0 0 0 -.083 -1.32z" fill="currentColor" stroke-width="0"></path>
                                            </svg>
                                        @endif
                                    </h1>
                                    <div class="my-2 space-y-1 text-xs text-muted md:text-sm dark:text-gray-300">
                                        <div class="text-center lg:text-left">Joined {{ $auth->created_at->format('d F, Y') }}</div>
                                        <div>{{ $auth->title_profile ?? 'Member active'  }}</div>
                                    </div>
                                    <div class="relative">
                                        <div class="absolute inset-0 flex items-center" aria-hidden="true">
                                          <div class="w-full border-t border-gray-300 dark:border-gray-800"></div>
                                        </div>
                                        <div class="relative flex lg:justify-start justify-center">
                                          <span class="dark:bg-slate-900 bg-slate-50 pr-0 lg:pr-3 text-sm text-gray-900 dark:text-gray-500">About</span>
                                        </div>
                                      </div>
                                    <div class="text-xs leading-relaxed text-invert md:text-base md:leading-8 dark:text-gray-200" id="typed-about" data-value="">{{ $auth->about ?? 'This profile has not been filled with information about me yet.' }}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="w-full lg:w-1/2">
                        <div class="flex justify-center md:justify-end gap-2 md:gap-4">
                            <div class="animate-fade-in-left-bounce bg-primary-500/20 dark:text-primary-400 text-primary-600 flex flex-col gap-y-4 text-center justify-center md:justify-between py-4 md:py-10 h-40 md:h-56 rounded-xl w-40">
                                <div class="flex items-center justify-center from-sky-500 to-violet-600 w-10 md:w-12 h-10 md:h-12 shrink-0 rounded-full mx-auto bg-gradient-to-br">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 md:w-6 md:h-6 stroke-[1.25] text-white" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                        <path d="M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0"></path>
                                        <path d="M14 9.75a3.016 3.016 0 0 0 -4.163 .173a2.993 2.993 0 0 0 0 4.154a3.016 3.016 0 0 0 4.163 .173"></path>
                                    </svg>
                                </div>
                                <div>
                                    <div class="font-bold text-xl sm:text-2xl">{{ $auth->_count_license() }}</div>
                                    <div class="text-black/50 text-[11px] md:text-sm dark:text-white/50">License</div>
                                </div>
                            </div>
                            <div class="animate-fade-in-left-bounce-2 bg-emerald-500/20 dark:text-emerald-400 text-emerald-600 flex flex-col gap-y-4 text-center justify-center md:justify-between py-4 md:py-10 h-40 md:h-56 rounded-xl w-40">
                                <div class="flex items-center justify-center from-emerald-500 to-lime-600 w-10 md:w-12 h-10 md:h-12 shrink-0 rounded-full mx-auto bg-gradient-to-br">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 md:w-6 md:h-6 stroke-[1.25] text-white" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                        <path d="M19.5 12.572l-7.5 7.428l-7.5 -7.428a5 5 0 1 1 7.5 -6.566a5 5 0 1 1 7.5 6.572"></path>
                                     </svg>
                                </div>
                                <div>
                                    <div class="font-bold text-xl sm:text-2xl">{{ $auth->_count_wishlist() }}</div>
                                    <div class="text-black/50 text-[11px] md:text-sm dark:text-white/50">Wishlist</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    </div>
</div>
@endsection
