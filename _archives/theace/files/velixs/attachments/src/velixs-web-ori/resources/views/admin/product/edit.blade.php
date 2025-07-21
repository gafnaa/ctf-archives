@extends('layouts.admin.main')

@section('title', 'Edit Product')

@section('content')
<form id="submit" action="{!! route('admin.product.update',$product->id) !!}">
    @csrf
    <div class="d-flex justify-content-end">
        <button class="btn btn-label-primary me-2 d-flex justify-content-center justify-items-center" name="button_submit" value="update" type="submit">
            <svg xmlns="http://www.w3.org/2000/svg" class="me-2" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                <path d="M7 18a4.6 4.4 0 0 1 0 -9a5 4.5 0 0 1 11 2h1a3.5 3.5 0 0 1 0 7h-1"></path>
                <path d="M9 15l3 -3l3 3"></path>
                <path d="M12 12l0 9"></path>
            </svg>Update
        </button>
        <button class="btn btn-primary" name="button_submit" value="update and exit" type="submit">
            <svg xmlns="http://www.w3.org/2000/svg" class="me-2" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                <path d="M17 11h1c1.38 0 3 1.274 3 3c0 1.657 -1.5 3 -3 3l-6 0v-10c3 0 4.5 1.5 5 4z"></path>
                <path d="M9 8l0 9"></path>
                <path d="M6 17l0 -7"></path>
                <path d="M3 16l0 -2"></path>
            </svg>Update &amp; Exit
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
                                <button type="button" class="nav-link" role="tab" data-bs-toggle="tab" data-bs-target="#navs-pills-justified-payment" aria-controls="navs-pills-justified-profile" aria-selected="false">
                                    <i class="tf-icons ti ti-credit-card ti-xs me-1" style="margin-top: -2px"></i> Payment
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
                            <label for="defaultFormControlInput" class="form-label">Name</label>
                            <input type="text" class="form-control" placeholder="Title Product" value="{{ $product->title }}" name="title" autocomplete="off">
                        </div>
                        <div class="row">
                            <div class="col-12 col-xl-6 col-lg-6">
                                <div class="mb-3">
                                    <label for="defaultFormControlInput" class="form-label">Slug</label>
                                    <input type="text" class="form-control" placeholder="slug" name="slug" value="{{ $product->slug }}" autocomplete="off">
                                </div>
                            </div>
                            <div class="col-12 col-xl-6 col-lg-6">
                                <div class="mb-3">
                                    <label for="defaultFormControlInput" class="form-label">Preview</label>
                                    <input type="text" class="form-control" placeholder="Url" value="{!! $product->preview !!}" name="preview" autocomplete="off">
                                </div>
                            </div>
                        </div>

                        <div class="mb-1">
                            <textarea name="content" id="content"></textarea>
                        </div>
                    </div>
                    <div class="tab-pane fade" id="navs-pills-justified-payment" role="tabpanel">
                        <div class="tab-pane active" id="payment-fill" role="tabpanel" aria-labelledby="payment-tab-fill">
                            <div class="row mb-3">
                                <div class="col-md mb-md-0 mb-2">
                                    <div class="form-check custom-option custom-option-basic content-product-type {{ $product->_isFree() ? '' : 'checked' }}">
                                        <label class="form-check-label custom-option-content" for="product_type1">
                                            <input class="form-check-input" type="radio" name="product_type" id="product_type1" value="pay" {{ $product->_isFree() ? '' : 'checked' }} />
                                            <span class="custom-option-header">
                                                <span class="h6 mb-0">Pay</span>
                                            </span>
                                            <span class="custom-option-body">
                                                <small class="d-block">This product will be sold according to the specified nominal.</small>
                                            </span>
                                        </label>
                                    </div>
                                </div>
                                <div class="col-md">
                                    <div class="form-check custom-option custom-option-basic content-product-type {{ $product->_isFree() ? 'checked' : '' }}">
                                        <label class="form-check-label custom-option-content" for="product_type2">
                                            <input class="form-check-input" type="radio" name="product_type" id="product_type2" value="free" {{ $product->_isFree() ? 'checked' : '' }} />
                                            <span class="custom-option-header">
                                                <span class="h6 mb-0">Free</span>
                                            </span>
                                            <span class="custom-option-body">
                                                <small class="d-block">All users can claim this license for free.</small>
                                            </span>
                                        </label>
                                    </div>
                                </div>
                            </div>
                            <div id="area_github" style="display: none">
                                <div class="row">
                                    <div class="col-12">
                                        <div class="mb-1">
                                            <label>GitHub Repository</label>
                                            <div class="input-group input-group-merge">
                                                <span class="input-group-text">
                                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                                        <path d="M9 19c-4.3 1.4 -4.3 -2.5 -6 -3m12 5v-3.5c0 -1 .1 -1.4 -.5 -2c2.8 -.3 5.5 -1.4 5.5 -6a4.6 4.6 0 0 0 -1.3 -3.2a4.2 4.2 0 0 0 -.1 -3.2s-1.1 -.3 -3.5 1.3a12.3 12.3 0 0 0 -6.2 0c-2.4 -1.6 -3.5 -1.3 -3.5 -1.3a4.2 4.2 0 0 0 -.1 3.2a4.6 4.6 0 0 0 -1.3 3.2c0 4.6 2.7 5.7 5.5 6c-.6 .6 -.6 1.2 -.5 2v3.5"></path>
                                                     </svg>
                                                </span>
                                                <input type="text" name="github" class="form-control" placeholder="//github.com/sya/repo" value="{!! $product->github !!}" autocomplete="off">
                                            </div>
                                            <small class="text-muted">Fill in this input if the 'Add Library' button should redirect to the GitHub repository. Leave it blank if you don't want to use GitHub.</small>
                                        </div>
                                    </div>
                                </div>

                            </div>
                            <div id="area_price" style="">
                                <div class="row">
                                    <div class="col-12 col-xl-6 col-lg-6">
                                        <div class="mb-1">
                                            <label>Price USD</label>
                                            <div class="input-group input-group-merge">
                                                <span class="input-group-text">$</span>
                                                <input type="text" name="price_usd" class="form-control" placeholder="10" value="{{ $product->_price('usd') }}" autocomplete="off">
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-12 col-xl-6 col-lg-6">
                                        <div class="mb-1">
                                            <label>Price IDR</label>
                                            <div class="input-group input-group-merge">
                                                <span class="input-group-text">IDR</span>
                                                <input type="text" name="price_idr" class="form-control" value="{{ $product->_price('idr') }}" placeholder="10000" autocomplete="off">
                                            </div>
                                        </div>
                                    </div>
                                </div>

                            </div>
                        </div>
                    </div>
                    <div class="tab-pane fade" id="navs-pills-justified-meta" role="tabpanel">
                        <div class="mb-3">
                            <label for="defaultFormControlInput" class="form-label">Meta Description</label>
                            <textarea class="form-control" name="meta_description" rows="6">{{ $product->meta_description }}</textarea>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-12 col-xl-4 col-lg-4">
            <div class="card mb-3">
                <div class="card-body p-3">
                    <h5 class="card-title">Tags</h5>
                    <input id="TagifyCustomInlineSuggestion" name="tags" class="form-control" value="{{ json_encode($product->_tags('title')) }}" placeholder="Select tags" />
                </div>
            </div>
            <div class="card mb-3">
                <div class="card-body p-3">
                    <img class="card-img mb-2" id="preview" src="{!! $product->_image() !!}" alt="">
                    <input class="form-control" onchange="loadFile(event)" type="file" name="image">
                </div>
            </div>
            <div class="card">
                <div class="card-body p-3">
                    <h5 class="card-title">Status</h5>
                    <select class="form-select" name="is_published">
                        <option {{ $product->is_published == 1 ? 'selected' : '' }} value="1">Published</option>
                        <option {{ $product->is_published == 2 ? 'selected' : '' }} value="2">Archived</option>
                        <option {{ $product->is_published == 0 ? 'selected' : '' }} value="0">Draft</option>
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

        @if ($product->_isFree())
            $('#area_price').hide();
            $('#area_github').show();
        @endif

        // radio change name product_type
        $('input[type=radio][name=product_type]').change(function() {
            $(".content-product-type").removeClass("checked");
            this.closest(".content-product-type").classList.add("checked");
            if (this.value == 'free') {
                $('#area_price').hide();
                $('#area_github').show();
            } else {
                $('#area_github').hide();
                $('#area_price').show();
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
            selector: '#content',
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
            setup: function(editor) {
                editor.on('init', function(e) {
                    editor.setContent(`{!! $product->content !!}`);
                });
            },
        });

        // submit on submit
        let button_submit = '';
        $('button[name=button_submit]').click(function() {
            button_submit = $(this).val();
        });
        $('#submit').submit(function(e) {
            e.preventDefault();
            var data = new FormData(this);
            data.append('content', tinymce.get('content').getContent());
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
                    // image set to null
                    $("input[name=image]").val("");
                    Swal.fire({
                        icon: 'success',
                        text: data.message,
                        customClass: {
                            confirmButton: 'btn btn-primary'
                        },
                        timer: 1500
                    });
                    $('button[name=button_submit]').attr('disabled', false);
                    setTimeout(() => {
                        if (button_submit == 'update and exit') {
                            window.location.href = "{!! route('admin.product.index') !!}";
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
