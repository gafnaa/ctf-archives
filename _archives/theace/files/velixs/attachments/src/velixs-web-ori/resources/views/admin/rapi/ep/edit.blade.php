@extends('layouts.admin.main')

@section('title', 'Edit EndPoint')

@section('content')
<form id="submit" action="{!! route('admin.rapi.endpoint.update', ['id'=>$api->id, 'epid'=>$ep->id]) !!}">
    @csrf
    <div class="d-flex justify-content-end">
        <button class="btn btn-label-primary me-2 d-flex justify-content-center justify-items-center" name="button_submit" value="update" type="submit">
            <svg xmlns="http://www.w3.org/2000/svg" class="me-2" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                <path d="M7 18a4.6 4.4 0 0 1 0 -9a5 4.5 0 0 1 11 2h1a3.5 3.5 0 0 1 0 7h-1"></path>
                <path d="M9 15l3 -3l3 3"></path>
                <path d="M12 12l0 9"></path>
            </svg>Save
        </button>
        <button class="btn btn-primary" name="button_submit" value="update and exit" type="submit">
            <svg xmlns="http://www.w3.org/2000/svg" class="me-2" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                <path d="M17 11h1c1.38 0 3 1.274 3 3c0 1.657 -1.5 3 -3 3l-6 0v-10c3 0 4.5 1.5 5 4z"></path>
                <path d="M9 8l0 9"></path>
                <path d="M6 17l0 -7"></path>
                <path d="M3 16l0 -2"></path>
            </svg>Update & Exit
        </button>
    </div>
    <hr>
    <div class="card">
        <div class="card-body">
            <div class="mb-3">
                <label class="form-label">Endpoint</label>
                <input type="text" name="url" placeholder="https://api.example.com/xxx" value="{{ $ep->url }}" class="form-control" required>
            </div>
            <div class="row">
                <div class="col-12 col-lg-6 col-md-6">
                    <div class="mb-3">
                        <label class="form-label">Name</label>
                        <input type="text" name="title" value="{{ $ep->title }}" placeholder="Name Endpoint" class="form-control" required>
                    </div>
                </div>
                <div class="col-12 col-lg-6 col-md-6">
                    <div class="mb-3">
                        <label class="form-label">Method</label>
                        <select name="method" class="form-control" required>
                            <option {{ $ep->method == 'GET' ? 'selected' : '' }} value="GET">GET</option>
                            <option {{ $ep->method == 'POST' ? 'selected' : '' }} value="POST">POST</option>
                        </select>
                    </div>
                </div>
            </div>

            <div data-tab="data">
                <div class="terminal-cuy shadow">
                    <div class="terminal-header">
                        <div>
                            <div style="padding: 5px; background: red; display: inline-block; border-radius: 100%"></div>
                            <div style="padding: 5px; background: orange; display: inline-block; border-radius: 100%"></div>
                            <div style="padding: 5px; background: green; display: inline-block; border-radius: 100%"></div>
                        </div>
                        <div style="font-size: 13px">~data</div>
                        <div></div>
                    </div>
                    <div class="editor language-json p-3 text-sm" data-defeaultvalue='{{ $ep->data ?? '{}' }}'></div>
                    <input id="input-content" type="hidden" name="data_body" value=''>
                </div>
            </div>

            <div data-tab="response-example">
                <div class="terminal-cuy shadow">
                    <div class="terminal-header">
                        <div>
                            <div style="padding: 5px; background: red; display: inline-block; border-radius: 100%"></div>
                            <div style="padding: 5px; background: orange; display: inline-block; border-radius: 100%"></div>
                            <div style="padding: 5px; background: green; display: inline-block; border-radius: 100%"></div>
                        </div>
                        <div style="font-size: 13px">~response-example</div>
                        <div></div>
                    </div>
                    <div class="editor language-json p-3 text-sm" data-defeaultvalue='{{ $ep->response ?? '{}' }}'></div>
                    <input id="input-content" type="hidden" name="data_response" value=''>
                </div>
            </div>
        </div>
    </div>

</form>
@endsection

@push('js')
    <script src="{{ asset('assets/highlight/highlight.min.js?v=21') }}"></script>
    <script type="module">
        import { CodeJar } from "{{ asset('assets/codejar.min.js') }}";
        const highlight = (editor) => {
            const parentDiv = editor.closest('[data-tab]');
            parentDiv.querySelector('#input-content').value = editor.textContent
            editor.textContent = editor.textContent;
            hljs.highlightBlock(editor);
        };

        const editorse = document.querySelectorAll(".editor");
        editorse.forEach((e)=>{
            const waduh = new CodeJar(e, highlight);
            waduh.updateCode(JSON.stringify(JSON.parse(e.dataset.defeaultvalue), null , 2))
        })



        // submit on submit
        let button_submit = '';
        $('button[name=button_submit]').click(function() {
            button_submit = $(this).val();
        });
        $('#submit').submit(function(e) {
            e.preventDefault();
            var data = new FormData(this);
            Swal.fire({
                html: '<div class="d-flex justify-content-center"><div class="sk-bounce sk-primary"><div class="sk-bounce-dot"></div><div class="sk-bounce-dot"></div></div></div><br>Loading...',
                allowOutsideClick: false,
                buttonsStyling: false,
                showConfirmButton: false,
            });
            $('button[name=button_submit]').attr('disabled', true);
            $.ajax({
                url: $(this).attr('action'),
                type: 'POST',
                data: data,
                cache: false,
                contentType: false,
                processData: false,
                success: function(data) {
                    $('button[name=button_submit]').attr('disabled', false);
                    Swal.fire({
                        icon: 'success',
                        text: data.message,
                        customClass: {
                            confirmButton: 'btn btn-primary'
                        },
                        timer: 1500
                    });
                    setTimeout(() => {
                        if (button_submit == 'update and exit') {
                            window.location.href = "{!! route('admin.rapi.endpoint',$api->id) !!}";
                        }
                    }, 1500);
                },
                error: function(data) {
                    $('button[name=button_submit]').attr('disabled', false);
                    Swal.fire({
                        icon: 'error',
                        text: data.responseJSON.message ?? 'Something went wrong!',
                        customClass: {
                            confirmButton: 'btn btn-primary'
                        },
                        timer: 1500
                    });
                }
            });
        });
    </script>
@endpush

@push('css')
    <link rel="stylesheet" href="{{ asset('assets/highlight/tokyo-night-dark.min.css') }}">
    <style>
        .terminal-cuy {
            overflow: hidden;
            border-radius: 6px;
            margin-top: 40px;
        }

        .terminal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            width: 100%;
            column-gap: 4px;
            padding-top: 4px;
            padding-bottom: 4px;
            padding-left: 12px;
            padding-right: 12px;
        }
    </style>
@endpush
