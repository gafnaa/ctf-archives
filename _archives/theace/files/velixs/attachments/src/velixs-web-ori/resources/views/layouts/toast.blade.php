<script src="{!! asset('assets/lazytoast.js?v=12') !!}"></script>
<script>
    const audioNotify = new Audio('{{ asset('assets/notify.mp3') }}');
    audioNotify.volume = 0.3;
    const toast = new LazyToast({
        duration: 4000,
        position: 'bottom-left',
    });
    function playN(){
        audioNotify.play();
    }
    @if (session()->has('info'))
        playN()
        toast.toast({
            style: 'info',
            title: '{{ session('info')['title'] ?? 'Info' }}',
            msg: '{{ session('info')['message'] ?? session('info') }}',
        })
    @elseif (session()->has('success'))
        playN()
        toast.toast({
            style: 'success',
            title: '{{ session('success')['title'] ?? 'Success' }}',
            msg: '{{ session('success')['message'] ?? session('success') }}',
        })
    @elseif (session()->has('warning'))
        playN()
        toast.toast({
            style: 'warning',
            title: '{{ session('warning')['title'] ?? 'Warning' }}',
            msg: '{{ session('warning')['message'] ?? session('warning') }}',
        })
    @elseif (session()->has('error'))
        playN()
        toast.toast({
            style: 'error',
            title: '{{ session('error')['title'] ?? 'Error' }}',
            msg: '{{ session('error')['message'] ?? session('error') }}',
        })
    @elseif (session()->has('bug'))
        playN()
        toast.toast({
            style: 'bug',
            title: '{{ session('bug')['title'] ?? 'Bug' }}',
            msg: '{{ session('bug')['message'] ?? session('bug') }}',
        })
    @endif

    @if ($errors->any())
        playN()
        @php
            $limit = 3;
        @endphp
        @foreach ($errors->all() as $error)
            @if ($loop->index == $limit)
                @break
            @endif
            toast.toast({
                style: 'error',
                title: 'Error',
                msg: '{{ $error }}',
            })
        @endforeach
    @endif
</script>
