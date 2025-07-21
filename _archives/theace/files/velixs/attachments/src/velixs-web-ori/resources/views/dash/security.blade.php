@extends('layouts.dash.main')

@section('content')
<main class="flex-1 dark:text-gray-50 text-gray-900">
    <div class="py-6">
        <div class="mx-auto lg:max-w-screen-xl px-6">
            <main class="flex animate-fade-in-bottom-bounce w-full flex-grow flex-col lg:flex-grow-0 lg:px-12 py-8">
                <div class="flex min-h-full flex-grow flex-col">
                    <h1 class="text-2xl font-bold">Security</h1>
                    <nav class="flex gap-x-2 text-sm items-center py-2 mb-5">
                        <div>Dashboard</div>
                        <div class="p-[2px] w-[2px] h-[2px] bg-gray-500 rounded-full"></div>
                        <div>User</div>
                        <div class="p-[2px] w-[2px] h-[2px] bg-gray-500 rounded-full"></div>
                        <div class="text-gray-500">Security</div>
                    </nav>

                    <div class="grid lg:grid-cols-12 gap-5">
                        <div class="lg:col-span-4">
                            <div class="bg-white dark:bg-gray-800 w-full border p-3 dark:border-gray-800 rounded-xl overflow-hidden">
                                <div class="flex justify-end">
                                    <div class="bg-green-400/40 text-green-600 dark:bg-green-600/40 dark:text-green-400 rounded-full p-1 px-3 text-[12px] font-semibold">Active</div>
                                </div>

                                <form class="flex justify-center mt-10 mb-5" id="avatar-settings" action="{!! route('dash.personal.axios.avatar') !!}">
                                    <label>
                                        <input name="avatar" accept="image/*" type="file" tabindex="-1" style="display: none;">
                                        <div class="group cursor-pointer relative border border-dashed p-2 rounded-full border-gray-400 dark:border-gray-600">
                                            <div class="w-32 h-32 aspect-w-1 rounded-full overflow-hidden bg-gray-200 dark:bg-gray-700">
                                                <img class="object-cover object-center w-full h-full" src="{{ $auth->_avatar() }}" alt="avatar">
                                                <div data-label-loading="" class="animate-pulse text-center mt-[38%] text-gray-400 hidden">....</div>
                                            </div>
                                            <div class="absolute transition-opacity text-center bg-gray-800/30 rounded-full w-32 h-32 top-2 opacity-0 group-hover:opacity-100 duration-300 ease-in-out">
                                                <div class="flex justify-center mt-10">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-gray-50" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M12 20h-7a2 2 0 0 1 -2 -2v-9a2 2 0 0 1 2 -2h1a2 2 0 0 0 2 -2a1 1 0 0 1 1 -1h6a1 1 0 0 1 1 1a2 2 0 0 0 2 2h1a2 2 0 0 1 2 2v3"></path>
                                                        <path d="M14.973 13.406a3 3 0 1 0 -2.973 2.594"></path>
                                                        <path d="M19.001 19m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0"></path>
                                                        <path d="M19.001 15.5v1.5"></path>
                                                        <path d="M19.001 21v1.5"></path>
                                                        <path d="M22.032 17.25l-1.299 .75"></path>
                                                        <path d="M17.27 20l-1.3 .75"></path>
                                                        <path d="M15.97 17.25l1.3 .75"></path>
                                                        <path d="M20.733 20l1.3 .75"></path>
                                                    </svg>
                                                </div>
                                                <div class="text-[11px] text-gray-50">Change Avatar</div>
                                            </div>
                                        </div>
                                    </label>
                                </form>
                                <div class="text-center mb-4 text-[12px] px-10 dark:text-gray-400">Allowed *.jpeg, *.jpg, *.png max size of 3.1 MB</div>
                                <div class="flex items-center justify-between py-5 px-3">
                                    <span class="flex flex-grow flex-col">
                                        <span class="text-sm font-medium text-gray-900 dark:text-gray-50">Private Profile <span id="loading-for-toggle-private-profile" class="text-gray-500 text-[11px] dark:text-gray-400 animate-pulse hidden">Loading...</span></span>
                                        <span class="text-sm text-gray-500 text-[11px] dark:text-gray-400">Hide email information and whatsapp number.</span>

                                    </span>
                                    <button id="toggle-private-profile" x-data="{ toggle: {{ $auth->private=='yes' ? 'true' : 'false' }} }" @click="toggle =! toggle" :class="{'bg-primary-600 dark:bg-primary-600': toggle }" type="button" class="bg-gray-200 dark:bg-gray-600 relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out">
                                        <span :class="{'translate-x-5': toggle }" class="translate-x-0 pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"></span>
                                    </button>
                                </div>
                            </div>
                        </div>
                        <div class="lg:col-span-8">
                            <form action="{!! route('dash.security.axios.update') !!}" id="form-update-profile">
                                <div class="bg-white dark:bg-gray-800 w-full border px-5 pb-5 pt-7 dark:border-gray-800 rounded-xl overflow-hidden">
                                    <div class="grid md:grid-cols-2 gap-3 gap-y-5">
                                        <div class="md:col-span-1">
                                            <div class="relative rounded-md border border-gray-300 dark:border-gray-700 px-3 py-2 shadow-sm focus-within:border-gray-600 focus-within:ring-0 focus-within:ring-gray-600"">
                                                <label class="absolute -top-2 left-2 -mt-px inline-block bg-white dark:bg-gray-800 px-1 text-xs font-medium text-gray-900 dark:text-gray-50">Current Password</label>
                                                <input autocomplete="off" type="text" name="current_password" class="block w-full py-1 border-0 p-0 text-gray-900 dark:text-gray-50 bg-transparent placeholder-gray-500 dark:placeholder-gray-400 focus:ring-0 sm:text-sm">
                                            </div>
                                        </div>
                                        <div class="md:col-span-1">
                                            <div class="relative rounded-md border border-gray-300 dark:border-gray-700 px-3 py-2 shadow-sm focus-within:border-gray-600 focus-within:ring-0 focus-within:ring-gray-600"">
                                                <label class="absolute -top-2 left-2 -mt-px inline-block bg-white dark:bg-gray-800 px-1 text-xs font-medium text-gray-900 dark:text-gray-50">New Password</label>
                                                <input autocomplete="off" type="text" name="new_password" class="block w-full py-1 border-0 p-0 text-gray-900 dark:text-gray-50 bg-transparent placeholder-gray-500 dark:placeholder-gray-400 focus:ring-0 sm:text-sm">
                                            </div>
                                        </div>
                                        <div class="md:col-span-1">
                                            <div class="relative rounded-md border border-gray-300 dark:border-gray-700 px-3 py-2 shadow-sm focus-within:border-gray-600 focus-within:ring-0 focus-within:ring-gray-600"">
                                                <label class="absolute -top-2 left-2 -mt-px inline-block bg-white dark:bg-gray-800 px-1 text-xs font-medium text-gray-900 dark:text-gray-50">Confirm Password</label>
                                                <input autocomplete="off" type="text" name="confirm_password" class="block w-full py-1 border-0 p-0 text-gray-900 dark:text-gray-50 bg-transparent placeholder-gray-500 dark:placeholder-gray-400 focus:ring-0 sm:text-sm">
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="bg-white dark:bg-gray-800 w-full border px-5 p-3 dark:border-gray-800 rounded-xl overflow-hidden mt-3">
                                    <div class="flex justify-end">
                                        <button type="submit" class="bg-primary-500 disabled:bg-primary-400 hover:scale-[1.02] transition-transform duration-300 ease-in-out flex justify-center items-center py-[0.60rem] px-5 font-semibold text-sm rounded-full text-white">
                                            Save Changes
                                        </button>
                                    </div>
                                </div>
                            </form>
                        </div>
                    </div>

                </div>
            </main>
        </div>
    </div>
</main>
@endsection


@push('js')
    <script>
        const debounce = (func, delay) => {
            let timer;
            return function (...args) {
                clearTimeout(timer);
                timer = setTimeout(() => {
                    func.apply(this, args);
                }, delay);
            };
        };

        // axios toggle private profile
        document.getElementById('toggle-private-profile').addEventListener('click', function(){
            document.getElementById('loading-for-toggle-private-profile').classList.remove('hidden');
            axios.get('{!! route('dash.personal.axios.toggle-private') !!}',{
                headers: {
                    'Content-Type': 'multipart/form-data',
                    'Accept': 'application/json',
                }
            }).then(function(response) {
                playN()
                toast.toast({
                    style: 'info',
                    title: response.data.title ?? 'Success',
                    msg: response.data.message ?? 'Success toggle private profile',
                })
                document.getElementById('loading-for-toggle-private-profile').classList.add('hidden');
            }).catch(function(error) {
                playN()
                toast.toast({
                    style: 'bug',
                    title: error.response.data.title ?? 'Spam detected',
                    msg: error.response.data.message ?? 'Error toggle private profile',
                })
                document.getElementById('loading-for-toggle-private-profile').classList.add('hidden');
            })
        });

        // axios update profile
        document.getElementById('form-update-profile').addEventListener('submit', function(e){
            e.preventDefault();
            button = this.querySelector('button[type="submit"]');
            button.disabled = true;
            button.innerHTML = 'Loading...';
            button.classList.add('animate-pulse', 'animate-bounce-in');
            const formData = new FormData(this);
            axios.post(this.action, formData,{
                headers: {
                    'Content-Type': 'multipart/form-data',
                    'Accept': 'application/json',
                }
            }).then(function(response) {
                toast.toast({
                    style: 'success',
                    title: response.data.title ?? 'Success',
                    msg: response.data.message ?? 'Password has been changed',
                })
                setTimeout(function(){
                    button.disabled = false;
                    button.innerHTML = 'Save Changes';
                    button.classList.remove('animate-pulse');
                }, 1000)
                document.getElementById('form-update-profile').reset();
            }).catch(function(error) {
                playN()
                toast.toast({
                    style: 'info',
                    title: error.response.data.title ?? 'Info',
                    msg: error.response.data.message ?? 'Something went wrong',
                })
                setTimeout(function(){
                    button.disabled = false;
                    button.innerHTML = 'Save Changes';
                    button.classList.remove('animate-pulse');
                }, 1000)
            })
        })

        //avatar
        const avatar = document.getElementById('avatar-settings');
        const avatarInput = avatar.querySelector('input[type="file"]');
        const avatarImage = avatar.querySelector('img');
        const avatarLoading = avatar.querySelector('[data-label-loading]');

        avatarInput.addEventListener('change', function(){
            avatarLoading.classList.remove('hidden');
            avatarImage.classList.add('hidden');
            const file = this.files[0];
            if(file){
                if(file.type.match(/image.*/)){
                    const reader = new FileReader();
                    const formData = new FormData(avatar);
                    axios.post(avatar.action, formData,{
                        headers: {
                            'Content-Type': 'multipart/form-data',
                            'Accept': 'application/json',
                        }
                    }).then(function(response) {
                        toast.toast({
                            style: 'success',
                            title: response.data.title ?? 'Success',
                            msg: response.data.message ?? 'Avatar has been changed',
                        })
                        avatarImage.setAttribute('src', response.data.avatar);
                        avatarImage.classList.remove('hidden');
                        avatarLoading.classList.add('hidden');
                    }).catch(function(error) {
                        playN()
                        toast.toast({
                            style: 'info',
                            title: error.response.data.title ?? 'Info',
                            msg: error.response.data.message ?? 'Something went wrong',
                        })
                        avatarImage.classList.remove('hidden');
                        avatarLoading.classList.add('hidden');
                    })
                }
            }
        })
    </script>
@endpush
