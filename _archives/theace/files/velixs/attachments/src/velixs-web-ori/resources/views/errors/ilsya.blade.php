<!DOCTYPE html>
<html lang="en" data-theme="dark" class="h-full">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $title ?? '-' }}</title>
    <link rel="stylesheet" href="https://rsms.me/inter/inter.css">
    @vite('resources/css/app.css')
    <meta name="robots" content="noindex, nofollow">
    <script>document.querySelector('html').setAttribute('data-theme', localStorage.getItem('theme-ilsya') ?? 'light');</script>
</head>

<body class="h-full dark:bg-gray-950">
    <div class="relative flex min-h-full flex-col pt-16 pb-12 overflow-hidden">
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
        <main class="mx-auto flex w-full max-w-7xl flex-grow flex-col justify-center px-6 lg:px-8">
            <div class="py-16">
                <div class="text-center">
                    <p class="text-base font-semibold text-indigo-600">{{ $code ?? '' }}</p>
                    <h1 class="mt-2 text-4xl font-bold tracking-tight text-gray-900 dark:text-gray-300 sm:text-5xl">{{ $title ?? '' }}.</h1>
                    <p class="mt-2 text-base text-gray-500 dark:text-gray-400">{{ $message ?? '' }}</p>
                    <div class="mt-6">
                        <a href="{!! route('main') !!}" class="text-base font-medium text-indigo-600 hover:text-indigo-500">
                            Back Home
                            <span aria-hidden="true"> &rarr;</span>
                        </a>
                    </div>
                </div>
            </div>
        </main>
        <footer class="mx-auto w-full max-w-7xl flex-shrink-0 px-6 lg:px-8">
            <nav class="flex justify-center space-x-4">
                <a href="{!! route('main') !!}" class="text-sm font-medium text-gray-500 hover:text-gray-600 dark:text-gray-300">Home</a>
                <span class="inline-block border-l border-gray-300 dark:border-gray-800" aria-hidden="true"></span>
                <a href="{!! route('product') !!}" class="text-sm font-medium text-gray-500 hover:text-gray-600 dark:text-gray-300">Product</a>
                <span class="inline-block border-l border-gray-300 dark:border-gray-800" aria-hidden="true"></span>
                <a href="{!! route('blog') !!}" class="text-sm font-medium text-gray-500 hover:text-gray-600 dark:text-gray-300">Blog</a>
            </nav>
        </footer>
    </div>
</body>

</html>
