@extends('layouts.admin.main')
@section('title', 'WebSettings')

@section('content')
<div class="row mt-4">
    <!-- Navigation -->
    <div class="col-lg-3 col-md-4 col-12 mb-md-0 mb-3">
        <div class="d-flex justify-content-between flex-column mb-2 mb-md-0">
            <ul class="nav nav-align-left nav-pills flex-column" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#meta" aria-selected="true" role="tab">
                        <i class="ti ti-code me-1 ti-sm"></i>
                        <span class="align-middle fw-semibold">Meta</span>
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" data-bs-toggle="tab" data-bs-target="#sl" aria-selected="false" role="tab" tabindex="-1">
                        <i class="ti ti-brand-meta me-1 ti-sm"></i>
                        <span class="align-middle fw-semibold">Social Links</span>
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" data-bs-toggle="tab" data-bs-target="#contact" aria-selected="false" role="tab" tabindex="-1">
                        <i class="ti ti-address-book me-1 ti-sm"></i>
                        <span class="align-middle fw-semibold">Contact</span>
                    </button>
                </li>
            </ul>
        </div>
    </div>
    <!-- /Navigation -->

    <!-- FAQ's -->
    <div class="col-lg-9 col-md-8 col-12">
        <div class="tab-content py-0">
            <div class="tab-pane fade active show" id="meta" role="tabpanel">
                <div class="d-flex mb-3 gap-3">
                    <div>
                        <span class="badge bg-label-primary rounded-2 p-2">
                            <i class="ti ti-code ti-lg"></i>
                        </span>
                    </div>
                    <div>
                        <h4 class="mb-0">
                            <span class="align-middle">Meta</span>
                        </h4>
                        <small>Manage your website meta data</small>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <form class="form-update" action="{!! route('admin.settings.update.meta') !!}" method="post">
                            @csrf
                            <div class="row">
                                <div class="col-12 col-xl-6 col-lg-6">
                                    <div class="mb-3">
                                        <label>Title</label>
                                        <input type="text" class="form-control" name="meta_title" value="{{ $ws->meta_title }}">
                                    </div>
                                </div>
                                <div class="col-12 col-xl-6 col-lg-6">
                                    <div class="mb-3">
                                        <label>Keywords</label>
                                        <input type="text" class="form-control" name="meta_keywords" value="{{ $ws->meta_keywords }}">
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="mb-3">
                                        <label>Logo</label>
                                        <input type="text" class="form-control" name="logo" value="{{ $ws->logo }}">
                                    </div>
                                </div>
                                <div class="col-12 col-xl-6 col-lg-6">
                                    <div class="mb-3">
                                        <label>Thumbnail</label>
                                        <input type="text" class="form-control" name="meta_thumbnail" value="{{ $ws->meta_thumbnail }}">
                                    </div>
                                </div>
                                <div class="col-12 col-xl-6 col-lg-6">
                                    <div class="mb-3">
                                        <label>Favicon</label>
                                        <input type="text" class="form-control" name="favicon" value="{{ $ws->favicon }}">
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="mb-3">
                                        <label>Description</label>
                                        <textarea name="meta_description" class="form-control" rows="5">{{ $ws->meta_description }}</textarea>
                                    </div>
                                </div>
                            </div>
                            <div class="text-end">
                                <button class="btn btn-label-success btn-generate-sitemap" type="button">Generate SiteMap</button>
                                <button class="btn btn-label-primary" type="submit">Update</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            <div class="tab-pane fade " id="sl" role="tabpanel">
                <div class="d-flex mb-3 gap-3">
                    <div>
                        <span class="badge bg-label-primary rounded-2 p-2">
                            <i class="ti ti-brand-meta ti-lg"></i>
                        </span>
                    </div>
                    <div>
                        <h4 class="mb-0">
                            <span class="align-middle">Social Links</span>
                        </h4>
                        <small>Manage your website social links</small>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <form class="form-update" action="{!! route('admin.settings.update.social') !!}" method="post">
                            @csrf
                            <div class="text-end">
                                <button class="btn btn-primary btn-create-social" type="button">Add Row</button>
                            </div>
                            <div id="social-links">
                                @foreach ($socials as $social)
                                    <div class="row container-social-links">
                                        <div class="col-12 col-xl-3 mb-3">
                                            <label>Name</label>
                                            <input type="text" name="name[]" value="{{ $social->name }}" class="form-control" required placeholder="Facebook">
                                        </div>
                                        <div class="col-12 col-xl-4 mb-3">
                                            <label>svg</label>
                                            <input type="text" name="svg[]" value="{{ $social->svg }}" class="form-control" required placeholder="<svg ....">
                                        </div>
                                        <div class="col-12 col-xl-3 mb-3">
                                            <label>url</label>
                                            <input type="text" name="url[]" value="{!! $social->url !!}" class="form-control" required placeholder="//facebook.com/pages">
                                        </div>
                                        <div class="col-12 col-xl-2 d-flex align-items-end mb-3">
                                            <button class="btn btn-label-danger btn-delete" type="button">Delete</button>
                                        </div>
                                    </div>
                                    <hr>
                                @endforeach
                            </div>
                            <div class="text-end mt-3">
                                <button class="btn btn-label-primary" type="submit">Update</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            <div class="tab-pane fade " id="contact" role="tabpanel">
                <div class="d-flex mb-3 gap-3">
                    <div>
                        <span class="badge bg-label-primary rounded-2 p-2">
                            <i class="ti ti-address-book ti-lg"></i>
                        </span>
                    </div>
                    <div>
                        <h4 class="mb-0">
                            <span class="align-middle">Contact</span>
                        </h4>
                        <small>Manage your website contact data</small>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <form class="form-update" action="{!! route('admin.settings.update.contact') !!}" method="post">
                            @csrf
                            <div class="row">
                                <div class="col-12 col-xl-6 col-lg-6">
                                    <div class="mb-3">
                                        <label>Whatsapp Payment</label>
                                        <input type="text" class="form-control" name="payment_whatsapp" value="{{ $ws->payment_whatsapp }}">
                                    </div>
                                </div>
                                <div class="col-12 col-xl-6 col-lg-6">
                                    <div class="mb-3">
                                        <label>Whatsapp Bot</label>
                                        <input type="text" class="form-control" name="bot_whatsapp" value="{{ $ws->bot_whatsapp }}">
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="mb-3">
                                        <label>Contact Email</label>
                                        <input type="email" class="form-control" name="contact_email" value="{{ $ws->contact_email }}">
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="mb-3">
                                        <label>Contact Whatsapp</label>
                                        <textarea name="contact_whatsapp" class="form-control" rows="5">{{ $ws->contact_whatsapp }}</textarea>
                                    </div>
                                </div>
                            </div>
                            <div class="text-end">
                                <button class="btn btn-label-primary" type="submit">Update</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- /FAQ's -->
</div>
@endsection

@push('js')
    <script>
        $(".form-update").on("submit", function(e) {
            e.preventDefault();
            var form = $(this);
            form.find("[type=submit]").attr("disabled", true).text("Loading...");
            $.ajax({
                url: form.attr("action"),
                type: form.attr("method"),
                data: form.serialize(),
                success: function(response) {
                    Swal.fire({
                        icon: "success",
                        text: response.message ?? "Data updated successfully",
                        showConfirmButton: false,
                        timer: 1500,
                    });
                    form.find("[type=submit]").removeAttr("disabled").text("Update");
                },
                error: function(xhr) {
                    Swal.fire({
                        icon: "error",
                        text: xhr.responseJSON.message ?? "Something went wrong",
                        showConfirmButton: false,
                        timer: 1500,
                    });
                    form.find("[type=submit]").removeAttr("disabled").text("Update");
                },
            });
        });

        //add social links
        $(".btn-create-social").on('click',function(e){
            e.preventDefault();
            const html = ` <div class="row container-social-links"><div class="col-12 col-xl-3 mb-3"><label>Name</label><input type="text" name="name[]" value="" class="form-control" required placeholder="Facebook"></div><div class="col-12 col-xl-4 mb-3"><label>svg</label><input type="text" name="svg[]" value="" class="form-control" required placeholder="<svg ...."></div><div class="col-12 col-xl-3 mb-3"><label>url</label><input type="text" name="url[]" value="" class="form-control" required placeholder="//facebook.com/pages"></div><div class="col-12 col-xl-2 d-flex align-items-end mb-3"><button class="btn btn-label-danger btn-delete" type="button">Delete</button></div></div><hr>`
            $("#social-links").append(html);
        })

        // delete social links
        $(document).on('click','.btn-delete',function(e){
            e.preventDefault();
            // min 1 row
            if($("#social-links").children().length == 1){
                return Swal.fire({
                    icon: "error",
                    text: "Minimum 1 row required",
                    showConfirmButton: false,
                    timer: 1500,
                });
            }
            $(this).closest('.container-social-links').remove();
        })
    </script>
@endpush
