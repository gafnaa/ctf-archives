 <!-- pagination -->
 <div class="flex mt-8 sm:mt-12 lg:mt-20 justify-center relative">
    <div class="flex w-full items-center justify-between gap-x-2 md:hidden">
        @if ($paginator->onFirstPage())
            <button disabled class="opacity-50 flex items-center rounded-lg bg-slate-200/60 px-3 py-2 text-xs font-medium dark:bg-slate-700/50 dark:text-slate-200">
                {!! __('pagination.previous') !!}
            </button>
        @else
            <a href="{{ $paginator->previousPageUrl() }}" class="flex items-center rounded-lg bg-slate-200/60 px-3 py-2 text-xs font-medium dark:bg-slate-700/50 dark:text-slate-200">
                {!! __('pagination.previous') !!}
            </a>
        @endif

        @if ($paginator->hasMorePages())
            <a href="{{ $paginator->nextPageUrl() }}" class="flex items-center rounded-lg bg-slate-200/60 px-4 py-2 text-xs font-medium dark:bg-slate-700/50 dark:text-slate-200">
                {!! __('pagination.next') !!}
            </a>
        @else
            <button disabled href="{{ $paginator->nextPageUrl() }}" class="opacity-50 flex items-center rounded-lg bg-slate-200/60 px-4 py-2 text-xs font-medium dark:bg-slate-700/50 dark:text-slate-200">
                {!! __('pagination.next') !!}
            </button>
        @endif
    </div>
    <div class="hidden md:block">
        <ul class="flex items-center font-mono gap-x-1.5">
            @if ($paginator->onFirstPage())
                <li>
                    <div class="flex items-center justify-center h-10 w-12 pointer-events-none rounded-lg text-slate-400 bg-slate-200/60 dark:bg-slate-700/50 dark:text-slate-600">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-4 w-4">
                            <path d="M15 6l-6 6l6 6"></path>
                        </svg>
                    </div>
                </li>
            @else
                <li>
                    <a href="{{ $paginator->previousPageUrl() }}" class="flex items-center justify-center h-10 w-12 rounded-lg bg-slate-200/60 dark:bg-slate-700/50 dark:text-slate-200">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-4 w-4">
                            <path d="M15 6l-6 6l6 6"></path>
                        </svg>
                    </a>
                </li>
            @endif

            @foreach ($elements as $element)
                @if (is_array($element))
                    @foreach ($element as $page => $url)
                        @if ($page == $paginator->currentPage())
                            <li>
                                <div class="!text-indigo-500 pointer-events-none text-sm flex items-center justify-center h-10 w-12 rounded-lg bg-slate-200/60 dark:bg-slate-700/50 dark:text-slate-200">{{ $page }}</div>
                            </li>
                        @else
                            <li>
                                <a href="{{ $url }}" class="text-slate-700 text-sm flex items-center justify-center h-10 w-12 rounded-lg bg-slate-200/60 dark:bg-slate-700/50 dark:text-slate-200">{{ $page }}</a>
                            </li>
                        @endif
                    @endforeach
                @endif
            @endforeach

            @if ($paginator->hasMorePages())
                <li>
                    <a href="{{ $paginator->nextPageUrl() }}" class="flex items-center justify-center h-10 w-12 rounded-lg bg-slate-200/60 dark:bg-slate-700/50 dark:text-slate-200">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-4 w-4">
                            <path d="M9 6l6 6l-6 6"></path>
                        </svg>
                    </a>
                </li>
            @else
                <li>
                    <div class="pointer-events-none flex items-center justify-center h-10 w-12 rounded-lg text-slate-400 bg-slate-200/60 dark:bg-slate-700/50 dark:text-slate-600">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-4 w-4">
                            <path d="M9 6l6 6l-6 6"></path>
                        </svg>
                    </div>
                </li>
            @endif
        </ul>
    </div>
</div>
