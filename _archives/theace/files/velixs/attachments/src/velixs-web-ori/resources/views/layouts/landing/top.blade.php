<div
x-data="{ showButton: false }"
x-init="window.addEventListener('scroll', () => { showButton = window.pageYOffset > 100; })"
class="fixed bottom-4 right-4 lg:bottom-[3rem] lg:right-[4rem] z-50"
>
<button
    x-show="showButton"
    x-transition
    @click="window.scrollTo({ top: 0, behavior: 'smooth' })"
    class="animate-bounce bg-white dark:bg-slate-800 p-2 w-10 h-10 ring-1 ring-slate-900/5 dark:ring-slate-200/20 shadow-lg rounded-full flex items-center justify-center"
>
    <svg class="w-6 h-6 text-violet-500" fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" viewBox="0 0 24 24" stroke="currentColor">
      <path d="M5 10l7-7m0 0l7 7m-7-7v18"></path>
    </svg>
</button>
</div>
