@extends('layouts.admin.main')

@section('title', 'Create API')

@section('content')
<form id="submit" action="{!! route('admin.rapi.store') !!}">
    @csrf
    <div class="d-flex justify-content-end">
        <button class="btn btn-label-primary me-2 d-flex justify-content-center justify-items-center" name="button_submit" value="save" type="submit">
            <svg xmlns="http://www.w3.org/2000/svg" class="me-2" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                <path d="M7 18a4.6 4.4 0 0 1 0 -9a5 4.5 0 0 1 11 2h1a3.5 3.5 0 0 1 0 7h-1"></path>
                <path d="M9 15l3 -3l3 3"></path>
                <path d="M12 12l0 9"></path>
            </svg>Save
        </button>
        <button class="btn btn-primary" name="button_submit" value="save and edit" type="submit">
            <svg xmlns="http://www.w3.org/2000/svg" class="me-2" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                <path d="M17 11h1c1.38 0 3 1.274 3 3c0 1.657 -1.5 3 -3 3l-6 0v-10c3 0 4.5 1.5 5 4z"></path>
                <path d="M9 8l0 9"></path>
                <path d="M6 17l0 -7"></path>
                <path d="M3 16l0 -2"></path>
            </svg>Save & Edit
        </button>
    </div>
    <hr>
    <div class="row">
        <div class="col-12 col-xl-8 col-lg-8">
            <div class="nav-align-top mb-4">
                <div class="card mb-3">
                    <div class="card-body p-1">
                        <ul class="nav nav-pills nav-fill" role="tablist">
                            <li class="nav-item">
                                <button type="button" class="nav-link active" role="tab" data-bs-toggle="tab" data-bs-target="#navs-pills-justified-general" aria-controls="navs-pills-justified-home" aria-selected="true">
                                    <i class="tf-icons ti ti-world ti-xs me-1" style="margin-top: -2px"></i> General
                                </button>
                            </li>
                            <li class="nav-item">
                                <button type="button" class="nav-link" role="tab" data-bs-toggle="tab" data-bs-target="#navs-pills-justified-meta" aria-controls="navs-pills-justified-messages" aria-selected="false">
                                    <i class="tf-icons ti ti-code ti-xs me-1" style="margin-top: -2px"></i> Meta
                                </button>
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="tab-content card card-body rounded">
                    <div class="tab-pane fade show active" id="navs-pills-justified-general" role="tabpanel">
                        <div class="mb-3">
                            <label for="defaultFormControlInput" class="form-label">Title</label>
                            <input type="text" class="form-control" placeholder="Name Api" name="title" autocomplete="off">
                        </div>
                        <div class="row">
                            <div class="col-12">
                                <div class="mb-3">
                                    <label for="defaultFormControlInput" class="form-label">Slug</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control" placeholder="slug" name="slug" autocomplete="off">
                                        <button class="btn btn-primary waves-effect" type="button" id="btn-generate-slug">Genereate</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="mb-1">
                            <label class="form-label">ReadMe</label>
                            <textarea name="readme" id="readme"></textarea>
                        </div>
                    </div>
                    <div class="tab-pane fade" id="navs-pills-justified-meta" role="tabpanel">
                        <div class="mb-3">
                            <label for="defaultFormControlInput" class="form-label">Meta Description</label>
                            <textarea class="form-control" name="meta_description" rows="6"></textarea>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-12 col-xl-4 col-lg-4">
            <div class="card mb-3">
                <div class="card-body p-3">
                    <h5 class="card-title">Tags</h5>
                    <input id="TagifyCustomInlineSuggestion" name="tags" class="form-control" placeholder="Select tags" />
                </div>
            </div>
            <div class="card mb-3">
                <div class="card-body p-3 text-center">
                    <img class="card-img mb-2" style="height: 8rem; width: 8rem" id="preview" src="https://via.placeholder.com/175x175.png?text=thumbnail" alt="">
                    <input class="form-control" onchange="loadFile(event)" type="file" name="image">
                </div>
            </div>
            <div class="card">
                <div class="card-body p-3">
                    <h5 class="card-title">Status</h5>
                    <select class="form-select" name="is_published">
                        <option value="1">Active</option>
                        <option value="0">Draft</option>
                    </select>
                </div>
            </div>
        </div>
    </div>


</form>
@endsection

@push('css')
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/tagify/tagify.css" />
@endpush

@push('js')
    <script src="{!! asset('assets/dash') !!}/vendor/libs/tagify/tagify.js"></script>
    <script src="{!! asset('assets/dash') !!}/tinymce/tinymce.min.js"></script>
    <script>
        const whitelist = {!! json_encode($tags) !!};
        new Tagify(document.querySelector('#TagifyCustomInlineSuggestion'), {
            whitelist: JSON.parse(whitelist),
            maxTags: 10,
            dropdown: {
                maxItems: 20,
                classname: 'tags-inline',
                enabled: 0,
                closeOnSelect: false
            }
        });

        function loadFile(event) {
            var output = document.getElementById('preview');
            output.src = URL.createObjectURL(event.target.files[0]);
        };

        $(document).on('keyup', 'input[name="slug"]', function() {
            var Text = $(this).val();
            Text = Text.toLowerCase();
            Text = Text.replace(/[^a-zA-Z0-9]+/g, '-');
            $(this).val(Text);
        });

        tinymce.init({
            selector: '#readme',
            plugins: 'link lists image advlist fullscreen media code table emoticons hr preview codesample',
            height: 400,
            menubar: false,
            relative_urls: false,
            remove_script_host: false,
            convert_urls: true,
            toolbar: [
                'formatselect bold italic underline strikethrough forecolor backcolor bullist numlist blockquote subscript superscript alignleft aligncenter alignright alignjustify image media link table hr removeformat preview code codesample fullscreen',
            ],
            codesample_languages: [
                { text: 'JSON', value: 'json' },
                { text: 'HTML/XML', value: 'html' },
                { text: 'JavaScript', value: 'javascript' },
                { text: 'CSS', value: 'css' },
                { text: 'PHP', value: 'php' },
                { text: 'Ruby', value: 'ruby' },
                { text: 'Python', value: 'python' },
                { text: 'Java', value: 'java' },
                { text: 'C', value: 'c' },
                { text: 'C#', value: 'csharp' },
                { text: 'C++', value: 'cpp' }
            ],
            file_picker_callback(callback, value, meta) {
                let x = window.innerWidth || document.documentElement.clientWidth || document.getElementsByTagName('body')[0].clientWidth
                let y = window.innerHeight || document.documentElement.clientHeight || document.getElementsByTagName('body')[0].clientHeight

                tinymce.activeEditor.windowManager.openUrl({
                    url: '{{ route('admin.files.fortinymce') }}',
                    title: 'File manager',
                    width: x * 1,
                    height: y * 1,
                    onMessage: (api, message) => {
                        callback(message.content, {
                            text: message.text
                        })
                    }
                })
            },
        });

        $("#btn-generate-slug").click((e)=>{
            e.preventDefault();
            $.ajax({
                url: "{{ route('admin.rapi.gslug.ajax') }}",
                type: "GET",
                success : (res)=>{
                    var Text = res.slug
                    Text = Text.toLowerCase();
                    Text = Text.replace(/[^a-zA-Z0-9]+/g, '-');
                    $("#submit input[name=slug]").val(Text);
                },
                error : (res)=>{
                    Swal.fire({
                        icon: 'error',
                        text: res.responseJSON.message ?? 'Something went wrong!',
                        customClass: {
                            confirmButton: 'btn btn-primary'
                        },
                        timer: 1500
                    });
                }
            })
        })

        // submit on submit
        let button_submit = '';
        $('button[name=button_submit]').click(function() {
            button_submit = $(this).val();
        });
        $('#submit').submit(function(e) {
            e.preventDefault();
            var data = new FormData(this);
            data.append('readme', tinymce.get('readme').getContent());
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
                    Swal.fire({
                        icon: 'success',
                        text: data.message,
                        customClass: {
                            confirmButton: 'btn btn-primary'
                        },
                        timer: 1500
                    });
                    setTimeout(() => {
                        if (button_submit == 'save') {
                            window.location.href = "{!! route('admin.rapi.index') !!}";
                        } else {
                            window.location.href = data.redirect_edit;
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
