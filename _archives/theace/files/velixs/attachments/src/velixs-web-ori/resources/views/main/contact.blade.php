@extends('layouts.landing.main')

@section('content')

<div class="relative lg:h-[100vh] flex items-center justify-center overflow-hidden">
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
    <div class="mx-auto max-w-7xl lg:grid lg:grid-cols-5 my-14 lg:my-0 ">
        <div class="py-16 px-6 lg:col-span-2 lg:px-8 lg:py-24 xl:pr-12 animate-fade-in-right-bounce">
            <div class="mx-auto max-w-lg">
                <h2 class="text-2xl font-bold tracking-tight text-gray-900 sm:text-3xl dark:text-gray-100">Need help? Contact us</h2>
                <p class="mt-3 text-lg leading-6 text-gray-500 dark:text-gray-300">Looking for help? Drop your contact details here.</p>
                <dl class="mt-8 text-base text-gray-500 dark:text-gray-300">
                    <div class="mt-6">
                        <dt class="sr-only">Phone number</dt>
                        <dd class="flex">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 flex-shrink-0 text-gray-400" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                <path d="M3 21l1.65 -3.8a9 9 0 1 1 3.4 2.9l-5.05 .9"></path>
                                <path d="M9 10a.5 .5 0 0 0 1 0v-1a.5 .5 0 0 0 -1 0v1a5 5 0 0 0 5 5h1a.5 .5 0 0 0 0 -1h-1a.5 .5 0 0 0 0 1"></path>
                             </svg>
                             @foreach ($ws->_contact_whatsapp() as $index => $_cw)
                                <span class="ml-3">{{ $index. " ". $_cw }}</span>
                             @endforeach
                        </dd>
                    </div>
                    <div class="mt-3">
                        <dt class="sr-only">Email</dt>
                        <dd class="flex">
                            <!-- Heroicon name: outline/envelope -->
                            <svg class="h-6 w-6 flex-shrink-0 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
                            </svg>
                            <span class="ml-3">{{ $ws->contact_email }}</span>
                        </dd>
                    </div>
                </dl>
                <p class="mt-6 text-base text-gray-500 dark:text-gray-300">
                    Looking for careers?
                    <a href="#" class="font-medium text-gray-700 dark:text-primary-400 underline">View all job openings.</a>
                </p>
            </div>
        </div>
        <div class="px-6 lg:col-span-3 lg:py-24 lg:px-8 xl:pl-12 animate-fade-in-left-bounce">
            <div class="mx-auto max-w-lg lg:max-w-none">
                <form id="submitcontact" method="POST" class="grid grid-cols-1 gap-y-6">
                    <div class="grid lg:grid-cols-12 gap-4">
                        <div class="col-span-6">
                            <div>
                                <label for="full-name" class="sr-only">Full name</label>
                                <input type="text" name="full-name" id="full-name" autocomplete="off" class="block dark:bg-gray-900 dark:text-gray-200 dark:border-gray-800 w-full rounded-md border-gray-300 py-3 px-4 placeholder-gray-500 shadow-sm focus:ring-0" placeholder="Full name">
                            </div>
                        </div>
                        <div class="col-span-6">
                            <div>
                                <label for="email" class="sr-only">Email</label>
                                <input id="email" name="email" type="email" autocomplete="off" class="block dark:bg-gray-900 dark:text-gray-200 dark:border-gray-800 w-full rounded-md border-gray-300 py-3 px-4 placeholder-gray-500 shadow-sm focus:ring-0" placeholder="Email">
                            </div>
                        </div>
                    </div>
                    <div>
                        <label for="subject" class="sr-only">Subject</label>
                        <input id="subject" name="subject" type="text" autocomplete="off" class="block dark:bg-gray-900 dark:text-gray-200 dark:border-gray-800 w-full rounded-md border-gray-300 py-3 px-4 placeholder-gray-500 shadow-sm focus:ring-0" placeholder="Subject">
                    </div>
                    <div>
                        <label for="message" class="sr-only">Message</label>
                        <textarea id="message" name="message" rows="4" class="block dark:bg-gray-900 dark:text-gray-200 dark:border-gray-800 w-full rounded-md border-gray-300 py-3 px-4 placeholder-gray-500 shadow-sm focus:ring-0" placeholder="Message"></textarea>
                    </div>
                    <div class="flex justify-end animate-fade-in-left-bounce">
                        <button type="submit" class="btn-gradient py-2 px-5 w-full lg:w-auto rounded-full text-gray-100 font-semibold flex justify-center items-center">
                            Submit
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 ml-1.5" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                <path d="M5 12l14 0"></path>
                                <path d="M15 16l4 -4"></path>
                                <path d="M15 8l4 4"></path>
                             </svg>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
@include('layouts.landing.footer')
@endsection

@push('js')
    <script>
        document.getElementById('submitcontact').addEventListener('submit', function(e) {
            e.preventDefault();
            toast.toast({
                style: 'info',
                title: 'Oops!',
                msg: 'This feature is under development.',
            })
        });
    </script>
@endpush
