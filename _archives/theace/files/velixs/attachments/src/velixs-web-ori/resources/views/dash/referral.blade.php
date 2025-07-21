@extends('layouts.dash.main')

@section('content')
<main class="flex-1 dark:text-gray-50 text-gray-900">
    <div class="py-6">
        <div class="mx-auto px-4 sm:px-6 md:px-8">
            <h1 class="md:text-2xl text-xl font-semibold animate-fade-in-left-bounce-3">Referral & Withdrawals</h1>

            <main class="flex animate-fade-in-bottom-bounce w-full flex-grow flex-col lg:flex-grow-0 lg:px-12 py-8">
                <div class="flex min-h-full flex-grow flex-col">

                    <div class="grid grid-cols-12 gap-5">
                        <div class="md:col-span-4 col-span-6">
                            <div class="animate-fade-in-left-bounce bg-primary-500/20 dark:text-primary-400 gap-3 text-primary-600 flex md:flex-row flex-col md:text-start text-center justify-center py-10 rounded-xl">
                                <div class="flex md:mx-0 mx-auto items-center justify-center from-sky-500 to-violet-600 w-10 md:w-12 h-10 md:h-12 rounded-full bg-gradient-to-br">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 md:w-6 md:h-6 stroke-[1.25] text-white" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                        <path d="M9.5 3h5a1.5 1.5 0 0 1 1.5 1.5a3.5 3.5 0 0 1 -3.5 3.5h-1a3.5 3.5 0 0 1 -3.5 -3.5a1.5 1.5 0 0 1 1.5 -1.5z"></path>
                                        <path d="M4 17v-1a8 8 0 1 1 16 0v1a4 4 0 0 1 -4 4h-8a4 4 0 0 1 -4 -4z"></path>
                                    </svg>
                                </div>
                                <div>
                                    <div class="font-bold md:text-xl text-base">{{ number_format($auth->saldo, 2, ',','.') }}</div>
                                    <div class="text-black/50 text-[11px] md:text-sm dark:text-white/50">Balance</div>
                                </div>
                            </div>
                        </div>
                        <div class="md:col-span-4 col-span-6">
                            <div class="animate-fade-in-left-bounce bg-green-500/20 dark:text-green-400 gap-3 text-green-600 flex md:flex-row flex-col md:text-start text-center justify-center py-10 rounded-xl">
                                <div class="flex md:mx-0 mx-auto items-center justify-center from-green-300 to-green-600 w-10 md:w-12 h-10 md:h-12 rounded-full bg-gradient-to-br">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 md:w-6 md:h-6 stroke-[1.25] text-white" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                        <path d="M7 9m0 2a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2z"></path>
                                        <path d="M14 14m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0"></path>
                                        <path d="M17 9v-2a2 2 0 0 0 -2 -2h-10a2 2 0 0 0 -2 2v6a2 2 0 0 0 2 2h2"></path>
                                    </svg>
                                </div>
                                <div>
                                    <div class="font-bold md:text-xl text-base">{{ number_format($earnings_month, 2, ',','.') }}</div>
                                    <div class="text-black/50 text-[11px] md:text-sm dark:text-white/50">Earnings This Month</div>
                                </div>
                            </div>
                        </div>
                        <div class="md:col-span-4 col-span-12">
                            <div class="animate-fade-in-left-bounce bg-slate-500/20 dark:text-slate-400 gap-x-3 text-slate-600 flex justify-center py-10 rounded-xl">
                                <div class="flex items-center justify-center bg-slate-600 w-10 md:w-12 h-10 md:h-12 rounded-full">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 md:w-6 md:h-6 stroke-[1.25] text-white" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                        <path d="M9 14c0 1.657 2.686 3 6 3s6 -1.343 6 -3s-2.686 -3 -6 -3s-6 1.343 -6 3z"></path>
                                        <path d="M9 14v4c0 1.656 2.686 3 6 3s6 -1.344 6 -3v-4"></path>
                                        <path d="M3 6c0 1.072 1.144 2.062 3 2.598s4.144 .536 6 0c1.856 -.536 3 -1.526 3 -2.598c0 -1.072 -1.144 -2.062 -3 -2.598s-4.144 -.536 -6 0c-1.856 .536 -3 1.526 -3 2.598z"></path>
                                        <path d="M3 6v10c0 .888 .772 1.45 2 2"></path>
                                        <path d="M3 11c0 .888 .772 1.45 2 2"></path>
                                    </svg>
                                </div>
                                <div>
                                    <div class="font-bold text-xl">{{ number_format($total_payout, 2, ',','.') }}</div>
                                    <div class="text-black/50 text-[11px] md:text-sm dark:text-white/50">Total Payout</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="rounded-lg mt-5 -mb-1 bg-primary-600/90 dark:bg-primary-800 p-2 shadow-lg sm:p-3">
                        <div class="flex flex-wrap items-center justify-between">
                            <div class="flex w-0 flex-1 items-center">
                                <span class="flex rounded-lg bg-primary-800 dark:bg-primary-600 p-2">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-white" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                        <path d="M17 8v-3a1 1 0 0 0 -1 -1h-10a2 2 0 0 0 0 4h12a1 1 0 0 1 1 1v3m0 4v3a1 1 0 0 1 -1 1h-12a2 2 0 0 1 -2 -2v-12"></path>
                                        <path d="M20 12v4h-4a2 2 0 0 1 0 -4h4"></path>
                                    </svg>
                                </span>
                                <p class="ml-3 font-medium text-white">
                                    Anda memiliki Rp {{ number_format($auth->saldo, 2, ',', '.') }} untuk di withdraw. <br>
                                    <small>- Rate for paypal Rp 13.500 IDR / $1.00 USD</small>
                                    <br>
                                    <small>- Tidak termasuk fee</small>
                                </p>
                            </div>
                        </div>
                        <div class="mt-2 w-full flex-shrink-0 sm:order-2 sm:w-auto">
                            <button x-data @click="$store.modalwithdraw.toggle()" class="flex items-center justify-center w-full rounded-md border border-transparent bg-white px-4 py-2 text-sm font-semibold text-indigo-600 shadow-sm hover:bg-indigo-50">
                                Request Withdraw
                            </button>
                        </div>
                    </div>

                    <div x-data="{ tab: 'earnings' }">
                        <div class="border-b border-slate-200 dark:border-slate-700 mt-6">
                            <nav class="-mb-px flex" aria-label="Tabs">
                                <a href="javascript:void(0)" x-on:click="tab = 'earnings'" x-bind:class="{ '!border-indigo-500 !text-indigo-600': tab === 'earnings' }" class="border-transparent text-slate-500 w-1/2 py-4 px-1 text-center border-b-2 font-medium text-sm">
                                    Earnings
                                </a>
                                <a href="javascript:void(0)" x-on:click="tab = 'withdraw'" x-bind:class="{ '!border-indigo-500 !text-indigo-600': tab === 'withdraw' }" class="border-transparent text-slate-500 w-1/2 py-4 px-1 text-center border-b-2 font-medium text-sm">
                                    Withdraw
                                </a>
                            </nav>
                        </div>

                        <div class="tab-content">
                            <div x-show="tab == 'earnings'" class="tab-pane">
                                <div class="mt-5 flex flex-col" id="table-earnings">
                                    <div class="font-semibold text-sm md:text-base">- History Earnings</div>
                                    <div class="overflow-x-auto">
                                        <div class="inline-block min-w-full py-2 align-middle px-1">
                                            <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 rounded-lg">
                                                <table class="min-w-full divide-y divide-slate-300 dark:divide-slate-700">
                                                    <thead class="bg-slate-50 dark:bg-slate-800 dark:text-white text-slate-800">
                                                        <tr>
                                                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold">Date</th>
                                                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold">Total Amount</th>
                                                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold">Detail</th>
                                                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold">Status</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody class="divide-y divide-slate-200 dark:divide-slate-800 bg-white dark:bg-slate-800 dark:text-slate-50"></tbody>
                                                </table>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="text-end">
                                        <nav class="isolate inline-flex -space-x-px rounded-md shadow-sm" id="pagination">
                                            <button class="relative btn-prev inline-flex items-center rounded-l-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-2 text-sm font-medium text-gray-500 hover:bg-gray-50 focus:z-20">
                                                <span class="sr-only">Previous</span>
                                                <svg class="h-5 w-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M12.79 5.23a.75.75 0 01-.02 1.06L8.832 10l3.938 3.71a.75.75 0 11-1.04 1.08l-4.5-4.25a.75.75 0 010-1.08l4.5-4.25a.75.75 0 011.06.02z" clip-rule="evenodd" />
                                                </svg>
                                            </button>
                                            <button class="relative btn-next inline-flex items-center rounded-r-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-2 text-sm font-medium text-gray-500 hover:bg-gray-50 focus:z-20">
                                                <span class="sr-only">Next</span>
                                                <svg class="h-5 w-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd" />
                                                </svg>
                                            </button>
                                        </nav>
                                    </div>
                                </div>
                            </div>

                            <div x-show="tab == 'withdraw'" class="tab-pane">
                                <div class="mt-5 flex flex-col" id="table-withdraw">
                                    <div class="font-semibold text-sm md:text-base">- History Withdraw</div>
                                    <div class="overflow-x-auto">
                                        <div class="inline-block min-w-full py-2 align-middle px-1">
                                            <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 rounded-lg">
                                                <table class="min-w-full divide-y divide-slate-300 dark:divide-slate-700">
                                                    <thead class="bg-slate-50 dark:bg-slate-800 dark:text-white text-slate-800">
                                                        <tr>
                                                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold">Date</th>
                                                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold">Total Amount</th>
                                                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold">Method</th>
                                                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold">To</th>
                                                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold">Detal</th>
                                                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold">Status</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody class="divide-y divide-slate-200 dark:divide-slate-800 bg-white dark:bg-slate-800 dark:text-slate-50"></tbody>
                                                </table>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="text-end">
                                        <nav class="isolate inline-flex -space-x-px rounded-md shadow-sm" id="pagination">
                                            <button class="relative btn-prev inline-flex items-center rounded-l-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-2 text-sm font-medium text-gray-500 hover:bg-gray-50 focus:z-20">
                                                <span class="sr-only">Previous</span>
                                                <svg class="h-5 w-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M12.79 5.23a.75.75 0 01-.02 1.06L8.832 10l3.938 3.71a.75.75 0 11-1.04 1.08l-4.5-4.25a.75.75 0 010-1.08l4.5-4.25a.75.75 0 011.06.02z" clip-rule="evenodd" />
                                                </svg>
                                            </button>
                                            <button class="relative btn-next inline-flex items-center rounded-r-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-2 text-sm font-medium text-gray-500 hover:bg-gray-50 focus:z-20">
                                                <span class="sr-only">Next</span>
                                                <svg class="h-5 w-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd" />
                                                </svg>
                                            </button>
                                        </nav>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>


                </div>
            </main>

        </div>
    </div>
</main>

<div x-data x-show="$store.modalwithdraw.open" class="relative z-40" style="display: none" aria-labelledby="modal-title" role="dialog" aria-modal="true">
    <div x-show="$store.modalwithdraw.open" x-transition.opacity class="fixed inset-0 bg-slate-400/50 backdrop-blur-sm dark:bg-slate-800/40 transition-opacity"></div>
    <div class="fixed inset-0 z-10 overflow-y-auto">
        <div class="flex min-h-full justify-center p-4 text-center items-center sm:p-0">
            <div class="relative rounded-lg bg-white dark:bg-slate-900 px-4 pt-5 pb-4 text-left shadow-xl sm:my-8 w-full sm:max-w-lg sm:p-6 animate-bounce-in" x-show="$store.modalwithdraw.open" @click.outside="$store.modalwithdraw.toggle()" x-transition:leave="ease-in duration-200" x-transition:leave-start="opacity-100 scale-105" x-transition:leave-end="opacity-0 scale-0">
                <form id="form-withdraw" action="{{ route('dash.referral.withdraw') }}" method="POST">
                    @csrf
                    <div class="">
                        <h3 class="text-center text-lg font-medium leading-6 text-slate-900 dark:text-slate-100" id="modal-title">Request Withdraw</h3>
                        <div class="mt-4">
                            <div x-data="{ select : false }" id="select-payment">
                                <label class="block sm:text-sm text-xs font-medium text-slate-700 dark:text-slate-300">Payment</label>
                                <div class="relative mt-1">
                                    <button type="button" @click="select = ! select" class="relative w-full cursor-pointer rounded-md border border-slate-100 dark:border-none bg-white dark:bg-slate-800 py-2 pl-3 pr-10 text-left shadow-sm md:text-sm" aria-haspopup="listbox" aria-expanded="true" aria-labelledby="listbox-label">
                                        <span class="flex items-center">
                                            <span class="inline-block h-2 w-2 flex-shrink-0 rounded-full bg-green-400"></span>
                                            <span id="display-current" class="ml-3 block truncate dark:text-white text-sm md:text-base">-</span>
                                        </span>
                                        <span class="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2">
                                            <svg class="h-5 w-5 text-slate-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                <path fill-rule="evenodd" d="M10 3a.75.75 0 01.55.24l3.25 3.5a.75.75 0 11-1.1 1.02L10 4.852 7.3 7.76a.75.75 0 01-1.1-1.02l3.25-3.5A.75.75 0 0110 3zm-3.76 9.2a.75.75 0 011.06.04l2.7 2.908 2.7-2.908a.75.75 0 111.1 1.02l-3.25 3.5a.75.75 0 01-1.1 0l-3.25-3.5a.75.75 0 01.04-1.06z" clip-rule="evenodd" />
                                            </svg>
                                        </span>
                                    </button>
                                    <ul x-show="select" x-transition @click.outside="select = false" style="display: none" class="absolute z-10 mt-1 max-h-60 w-full overflow-auto rounded-md bg-white dark:bg-slate-800 py-1 text-base shadow-lg ring-1 ring-black dark:ring-0 ring-opacity-5 focus:outline-none sm:text-sm">
                                        @foreach ($payments as $index => $payment)
                                            <li @if ($payment['status']) @click="select = false" data-payment-click="{{ $payment['name'] }}" data-currency="{{ $payment['currency'] }}" data-section="{{ json_encode($payment['section']) }}" data-placeholder="{{ $payment['placeholder'] }}" @endif class="text-slate-900 dark:text-slate-100 relative hover:bg-slate-100 hover:dark:bg-slate-700 {{ $payment['status'] ? 'cursor-pointer' : 'cursor-not-allowed' }} cursor-pointer select-none py-2 pl-3 pr-9">
                                                <div class="flex items-center">
                                                    <span class="inline-block h-2 w-2 flex-shrink-0 rounded-full {{ $payment['status'] ? 'bg-green-400' : 'bg-slate-400' }}" aria-hidden="true"></span>
                                                    <span class="font-normal ml-3 block truncate text-sm md:text-base">
                                                        {{ $payment['name'] ?? '-' }}
                                                    </span>
                                                </div>
                                            </li>
                                        @endforeach
                                    </ul>
                                </div>
                            </div>
                        </div>

                        <div class="mt-4 hidden" id="input-payment">
                            <label for="payment" class="block sm:text-sm text-xs font-medium text-slate-700 dark:text-slate-300">Phone number</label>
                            <div class="mt-1">
                                <input type="hidden" name="method_payment">
                                <input type="text" name="payment" autocomplete="off" class="block w-full rounded-md border-slate-100 dark:border-none bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 shadow-sm text-sm md:text-base focus:ring-0 focus:border-slate-300" placeholder="me@example.com">
                            </div>
                        </div>

                        <div class="mt-4 hidden" id="select-amount">
                            <div class="flex flex-col items-center gap-1 mb-4 text-slate-900 dark:text-slate-200">
                                <small>Balance</small>
                                <p class="md:text-2xl text-xl font-bold">Rp {{ number_format($auth->saldo, 2, ',','.') }}</p>
                                <small>Rates Rp&nbsp;13.500 / $1.00</small>
                            </div>
                            <input type="hidden" name="amount">
                            <div class="flex gap-x-3 overflow-x-auto" id="amount-list">
                            </div>
                        </div>
                        <div class="text-xs mt-4 text-slate-900 dark:text-slate-200">
                            Please check back before requesting a withdrawal!
                        </div>
                        <div class="mt-4">
                            <button class="w-full text-sm font-semibold bg-primary-500 disabled:bg-primary-400 disabled:cursor-wait text-white p-2 rounded-md mb-2 flex items-center justify-center gap-x-2" type="submit">Withdraw</button>
                            <button @click="$store.modalwithdraw.toggle()" class="w-full text-sm font-semibold border border-dashed border-slate-300 dark:border-slate-400 text-slate-900 dark:text-slate-200 p-2 rounded-md" type="button">Cancel</button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
@endsection

@push('js')
    <script>
        document.addEventListener('alpine:init', () => {
            Alpine.store('modalwithdraw', {
                open: false,
                toggle() {
                    this.open = !this.open
                    if (this.open) {
                        document.body.classList.add('overflow-hidden');
                    } else {
                        document.body.classList.remove('overflow-hidden');
                    }
                }
            })
        })

        document.addEventListener('DOMContentLoaded',() => {
            const selectPayment = document.getElementById('select-payment')
            const inputPayment = document.getElementById('input-payment')
            const selectAmout = document.getElementById('select-amount')

            selectPayment.querySelectorAll('[data-payment-click]').forEach(el => {
                el.addEventListener('click', function(e){
                    e.preventDefault();
                    selectPayment.querySelector("#display-current").textContent = this.dataset.paymentClick
                    inputPayment.classList.remove('hidden')
                    inputPayment.querySelector('label').textContent = this.dataset.placeholder.split(':')[0] ?? '-'
                    inputPayment.querySelector('input[name="payment"]').placeholder = this.dataset.placeholder.split(':')[1] ?? '-'
                    inputPayment.querySelector('input[name="method_payment"]').value = this.dataset.paymentClick
                    selectAmout.classList.remove('hidden')
                    selectAmout.querySelector('input[name="amount"]').value = null
                    let amountList = selectAmout.querySelector('#amount-list')
                    amountList.innerHTML = ''
                    JSON.parse(this.dataset.section).forEach(el => {
                        amountList.innerHTML += `<label data-amount="${el['amount']}" class="radio-amount min-w-fit relative cursor-pointer rounded-lg border dark:border-none bg-white dark:bg-slate-800 p-5 shadow-sm focus:outline-none mb-1"><div class="flex flex-col items-center text-center gap-1.5"><svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-slate-700 dark:text-slate-300" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M9.5 3h5a1.5 1.5 0 0 1 1.5 1.5a3.5 3.5 0 0 1 -3.5 3.5h-1a3.5 3.5 0 0 1 -3.5 -3.5a1.5 1.5 0 0 1 1.5 -1.5z"></path><path d="M4 17v-1a8 8 0 1 1 16 0v1a4 4 0 0 1 -4 4h-8a4 4 0 0 1 -4 -4z"></path></svg><p class="font-semibold text-slate-800 dark:text-slate-50">${this.dataset.currency}&nbsp;${number_format(el['withdraw'], 2, ',', '.')}</p><small class="text-slate-700 dark:text-slate-300">Rp ${number_format(el['amount'], 2, ',', '.')}</small></div></label>`
                    })
                    amountList.querySelectorAll('.radio-amount').forEach(el => {
                        el.addEventListener('click', function(e){
                            e.preventDefault()
                            selectAmout.querySelector('input[name="amount"]').value = null
                            amountList.querySelectorAll('.radio-amount').forEach(el => {
                                el.classList.remove('border-primary-300','!bg-slate-50', 'dark:!bg-slate-600')
                            })
                            this.classList.add('border-primary-300','!bg-slate-50','dark:!bg-slate-600')

                            selectAmout.querySelector('input[name="amount"]').value = this.dataset.amount
                        })
                    })
                })
            })

            function number_format(amount, decimal, dec_point, thousands_sep) {
                decimal = decimal || 0;
                dec_point = dec_point || '.';
                thousands_sep = thousands_sep || ',';
                amount = parseFloat((amount + '').replace(/[^0-9+\-Ee.]/g, ''));
                var n = !isFinite(+amount) ? 0 : +amount,
                    prec = !isFinite(+decimal) ? 0 : Math.abs(decimal),
                    sep = (typeof thousands_sep === 'undefined') ? ',' : thousands_sep,
                    dec = (typeof dec_point === 'undefined') ? '.' : dec_point,
                    s = '',
                    toFixedFix = function (n, prec) {
                        var k = Math.pow(10, prec);
                        return '' + Math.round(n * k) / k;
                    };
                // Fix for IE parseFloat(0.55).toFixed(0) = 0;
                s = (prec ? toFixedFix(n, prec) : '' + Math.round(n)).split('.');
                if (s[0].length > 3) {
                    s[0] = s[0].replace(/\B(?=(?:\d{3})+(?!\d))/g, sep);
                }
                if ((s[1] || '').length < prec) {
                    s[1] = s[1] || '';
                    s[1] += new Array(prec - s[1].length + 1).join('0');
                }
                return s.join(dec);
            }

            document.querySelector("#form-withdraw").addEventListener("submit", (e)=>{
                e.preventDefault();
                e.target.querySelector('button[type="submit"]').disabled = true
                e.target.querySelector('button[type="submit"]').innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 animate-spin" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M12 3a9 9 0 1 0 9 9"></path></svg>Withdraw'
                let form = new FormData(e.target);
                axios.post(e.target.action, form).then((res)=>{
                    playN()
                    toast.toast({
                        style: res.data.style ?? 'info',
                        title: res.data.title ?? 'Success',
                        msg: res.data.message ?? 'Withdraw Success',
                    })
                    setTimeout(() => {
                        e.target.querySelector('button[type="submit"]').disabled = false
                        e.target.querySelector('button[type="submit"]').innerHTML = 'Withdraw'
                        window.location.reload()
                    }, 2000);
                }).catch((err)=>{
                    playN()
                    toast.toast({
                        style: err.response.data.style ?? 'info',
                        title: err.response.data.title ?? err.response.status,
                        msg: err.response.data.message ?? err.message,
                    })
                    setTimeout(() => {
                        e.target.querySelector('button[type="submit"]').disabled = false
                        e.target.querySelector('button[type="submit"]').innerHTML = 'Withdraw'
                    }, 2000);
                })
            })

            function tableAxios({
                table,
                cols,
                type = 'withdraw'
            }){
                table = document.querySelector(table)
                let currentPage = 1;
                function loadPage(page = ''){
                    axios.get("{{ route('dash.referral.transaction.axios') }}?page="+page+'&type='+type).then((res)=>{
                        const tbody = table.querySelector("tbody")
                        tbody.innerHTML = ''
                        const items = res.data.data;

                        items.forEach((item)=>{
                            let tr = `<tr>`
                            cols.forEach((col) => {
                                if(col=='status'){
                                    if(item.status=='approved'){
                                        tr += `<td class="whitespace-nowrap px-3 py-4 text-xs"><span class="bg-green-400 dark:bg-green-500 text-white px-[5px] py-[2px] rounded-full">${item[col]}</span></td>`
                                    }else if(item.status=='pending'){
                                        tr += `<td class="whitespace-nowrap px-3 py-4 text-xs"><span class="bg-amber-400 dark:bg-amber-500 text-white px-[5px] py-[2px] rounded-full">${item[col]}</span></td>`
                                    }else{
                                        tr += `<td class="whitespace-nowrap px-3 py-4 text-xs"><span class="bg-slate-400 dark:bg-slate-500 text-white px-[5px] py-[2px] rounded-full">${item[col]}</span></td>`
                                    }
                                }else{
                                    tr += `<td class="whitespace-nowrap px-3 py-4 text-sm">${item[col]}</td>`
                                }
                            })
                            tr += `</tr>`
                            tbody.innerHTML += tr
                        })

                        if(res.data.links[0]?.url) table.querySelector(".btn-prev").addEventListener("click", onPrevClick)
                        if(res.data.links.pop()?.url) table.querySelector(".btn-next").addEventListener("click", onNextClick)
                    })
                }
                function onPrevClick() { loadPage(currentPage - 1) }
                function onNextClick() { loadPage(currentPage + 1) }
                loadPage(currentPage)
            }

            tableAxios({
                table : "#table-withdraw",
                cols : ['created','amount', 'method', 'to', 'message_status', 'status'],
            })

            tableAxios({
                table : "#table-earnings",
                cols : ['created','amount', 'description', 'status'],
                type : 'earnings'
            })
        })
    </script>
@endpush
