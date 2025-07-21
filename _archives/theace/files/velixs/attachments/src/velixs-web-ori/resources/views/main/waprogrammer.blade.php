@extends('layouts.landing.main')

@section('content')
<div class="relative isolate overflow-hidden bg-white dark:bg-slate-950 min-h-screen lg:mt-0 mt-10">
    <svg viewBox="0 0 1108 632" aria-hidden="true" class="absolute top-10 left-[calc(50%-4rem)] -z-10 w-[69.25rem] max-w-none transform-gpu blur-3xl sm:left-[calc(50%-18rem)] lg:left-48 lg:top-[calc(50%-30rem)] xl:left-[calc(50%-24rem)]">
        <path fill="url(#175c433f-44f6-4d59-93f0-c5c51ad5566d)" fill-opacity=".2" d="M235.233 402.609 57.541 321.573.83 631.05l234.404-228.441 320.018 145.945c-65.036-115.261-134.286-322.756 109.01-230.655C968.382 433.026 1031 651.247 1092.23 459.36c48.98-153.51-34.51-321.107-82.37-385.717L810.952 324.222 648.261.088 235.233 402.609Z" />
        <defs>
            <linearGradient id="175c433f-44f6-4d59-93f0-c5c51ad5566d" x1="1220.59" x2="-85.053" y1="432.766" y2="638.714" gradientUnits="userSpaceOnUse">
                <stop stop-color="#4F46E5"></stop>
                <stop offset="1" stop-color="#80CAFF"></stop>
            </linearGradient>
        </defs>
    </svg>
    <div class="mx-auto max-w-7xl py-12 px-6 text-center lg:px-8 lg:py-24">
        <div class="space-y-8 sm:space-y-12">
            <div class="mb-16 sm:mx-auto sm:max-w-xl sm:space-y-4 lg:max-w-5xl">
                <h2 class="text-3xl font-bold tracking-tight sm:text-4xl dark:text-slate-50">Whatsapp Group Programmer</h2>
            </div>
            <ul role="list" class="mx-auto grid grid-cols-2 gap-x-4 gap-y-8 sm:grid-cols-4 md:gap-x-6 lg:max-w-5xl lg:gap-x-8 lg:gap-y-12 xl:grid-cols-4">
                @foreach ($groups as $group)
                    <a href="{!! $group->whatsapp_url !!}" target="_blank">
                        <div class="space-y-4">
                            <img class="wa-avatar shadow mx-auto h-20 w-20 rounded-full lg:h-24 lg:w-24" src="{!! $group->_image() !!}" alt="{{ $group->name }}">
                            <div class="space-y-2">
                                <div class="text-xs font-medium lg:text-sm">
                                    <h3 class="text-xs dark:text-slate-50">{{ $group->name }}</h3>
                                </div>
                            </div>
                        </div>
                    </a>
                @endforeach
            </ul>
        </div>
    </div>

    <div class="">
        <div class="mx-auto max-w-7xl py-24 px-6 lg:flex lg:items-center lg:py-32 lg:px-8">
            <div class="lg:w-0 lg:flex-1">
                <h2 class="text-3xl font-bold tracking-tight text-gray-900 sm:text-4xl dark:text-slate-50">Punya Group Programmer ?</h2>
                <p class="mt-3 max-w-3xl text-lg text-gray-500 dark:text-slate-400">
                    Jika teman-teman memiliki group programmer yang ingin di share, silahkan submit link groupnya dibawah ini, nanti akan admin review terlebih dahulu sebelum di publish.
                </p>
            </div>
            <div class="mt-8 lg:mt-0 lg:ml-8">
                <form class="sm:flex" id="submit-wa">
                    <label for="email-address" class="sr-only">Whatsapp Invite</label>
                    <input name="url" type="text" required class="w-full rounded-md input-versiku px-5 py-3 placeholder-gray-400 shadow-sm border sm:max-w-xs" placeholder="https://chat.whatsapp.com/example">
                    <div class="mt-3 rounded-md shadow sm:mt-0 sm:ml-3 sm:flex-shrink-0">
                        <button type="submit" class="flex w-full items-center justify-center gap-x-1 rounded-md border border-transparent bg-indigo-600 py-3 px-5 text-base font-medium text-white hover:bg-indigo-700">
                            Submit
                        </button>
                    </div>
                </form>
                <p class="mt-3 text-sm text-gray-500">
                    WhatsApp Group Invite
                </p>
            </div>
        </div>
    </div>

</div>

@include('layouts.landing.footer')
@endsection


@push('js')
    <script>
        document.getElementById('submit-wa').addEventListener('submit',function(e){
            e.preventDefault();
            this.querySelector('button').disabled = true;
            this.querySelector('button').innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 animate-spin" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M12 3a9 9 0 1 0 9 9"></path></svg>Submit';
            axios.post('{!! route('whatsapp.programmer.submit') !!}', new FormData(this)).then((res)=>{
                playN();
                toast.toast({
                    style: res.data.style ?? 'success',
                    title: res.data.title ?? res.status,
                    msg: res.data.message ?? 'Success'
                })
                this.reset();
                this.querySelector('button').disabled = false;
                this.querySelector('button').innerHTML = 'Submit';
            }).catch((err)=>{
                playN();
                toast.toast({
                    style: err.response.data.style ?? 'error',
                    title: err.response.data.title ?? err.response.data.status,
                    msg: err.response.data.message ?? 'Something went wrong'
                })
                this.reset();
                this.querySelector('button').disabled = false;
                this.querySelector('button').innerHTML = 'Submit';
            })
        })
    </script>
@endpush
