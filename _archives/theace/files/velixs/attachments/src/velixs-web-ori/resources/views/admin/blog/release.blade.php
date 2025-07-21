@extends('layouts.admin.main')

@section('title', 'Manage Relase')

@section('content')
<form action="{!! route('admin.product.release.update',$product->id) !!}" method="post" id="update-release">
    @csrf
    <div class="card">
        <div class="card-body">
            <small>Manage release</small>
            <h6>#{{ $product->title }}</h6>
            <hr>
            <div class="row">
                <div class="col-12 col-xl-6 col-lg-6">
                    <div class="mb-3">
                        <label for="latest-version">latest version</label>
                        <input class="form-control" type="text" placeholder="1.x" name="latest_version" value="{{ isset($product->release['latest']) ? $product->release['latest'] : '' }}" autocomplete="off">
                    </div>
                </div>
                <div class="col-12 col-xl-6 col-lg-6">
                    <div class="mb-3">
                        <label for="latest-version">latest url</label>
                        <input class="form-control" type="text" placeholder="//example.com/file.txt" value="{{ isset($product->release['latest_url']) ? $product->release['latest_url'] : '' }}" name="latest_url" autocomplete="off">
                    </div>
                </div>
            </div>

            <br><br>
            <div class="d-flex justify-content-between">
                <div>
                    <h6 class="mb-0">#Archive</h6>
                    <small>old version</small>
                </div>
                <button type="button" id="create-archive" class="btn btn-label-primary">New Version</button>
            </div>
            <br>
            <div id="archive-list">
                @foreach ($product->_archiveRelease() as $ar)
                    <div class="list"><div class="row"><div class="col-12 col-xl-5 col-lg-5"><div class="mb-3"><input class="form-control" value="{{ isset($ar['version']) ? $ar['version'] : '' }}" type="text" required placeholder="version" name="archive_version[]" autocomplete="off"></div></div><div class="col-12 col-xl-5 col-lg-5"><div class="mb-3"><input class="form-control" type="text" placeholder="url file" value="{{ isset($ar['url']) ? $ar['url'] : '' }}" required name="archive_url[]" autocomplete="off"></div></div><div class="col-12 col-xl-2 col-lg-2 d-flex align-items-end"><div class="mb-3"><button class="btn btn-label-danger btn-delete">Delete</button></div></div></div><hr class="m-0 mb-3"></div>
                @endforeach
            </div>
            <div class="mt-3 text-end">
                <a href="{!! route('admin.product.release.force',$product->id) !!}" class="btn btn-danger">Force all</a>
                <button class="btn btn-primary" type="submit">Update</button>
            </div>
        </div>
    </div>

</form>
@endsection

@push('js')
    <script>
        const btnCreateArchive = document.getElementById('create-archive');
        const archiveList = document.getElementById('archive-list');

        btnCreateArchive.addEventListener('click', () => {
            var html = `<div class="list"><div class="row"><div class="col-12 col-xl-5 col-lg-5"><div class="mb-3"><input class="form-control" type="text" required placeholder="version" name="archive_version[]" autocomplete="off"></div></div><div class="col-12 col-xl-5 col-lg-5"><div class="mb-3"><input class="form-control" type="text" placeholder="url file" required name="archive_url[]" autocomplete="off"></div></div><div class="col-12 col-xl-2 col-lg-2 d-flex align-items-end"><div class="mb-3"><button class="btn btn-label-danger btn-delete">Delete</button></div></div></div><hr class="m-0 mb-3"></div>`;
            archiveList.insertAdjacentHTML('beforeend', html);
        });


        archiveList.addEventListener('click', (e) => {
            if (e.target.classList.contains('btn-delete')) {
                e.target.closest('.list').remove();
            }
        });

        $("#update-release").submit(function(e) {
            e.preventDefault();
            var form = $(this);
            var url = form.attr('action');
            var data = form.serialize();
            form.find('button[type=submit]').prop('disabled', true);
            $.ajax({
                type: "POST",
                url: url,
                data: data,
                success: function(data) {
                    Swal.fire({
                        icon: 'success',
                        text: data.message ?? 'Success',
                        showConfirmButton: false,
                        timer: 1500
                    })
                    form.find('button[type=submit]').prop('disabled', false);
                },
                error: function(data) {
                    Swal.fire({
                        icon: 'error',
                        text: data.responseJSON.message ?? 'Error',
                        showConfirmButton: false,
                        timer: 1500
                    });
                    form.find('button[type=submit]').prop('disabled', false);
                }
            });
        });

    </script>
@endpush
