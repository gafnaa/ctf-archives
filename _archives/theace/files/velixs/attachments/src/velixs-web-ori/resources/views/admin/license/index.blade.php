@extends('layouts.admin.main')

@section('title', 'Manage License')

@section('content')
<div class="card">
    <div class="card-datatable table-responsive pt-0">
      <table class="ilsya-datatables table">
        <thead>
          <tr>
            <th></th>
            <th></th>
            <th>id</th>
            <th>key</th>
            <th>type</th>
            <th>item</th>
            <th>expires at</th>
          </tr>
        </thead>
      </table>
    </div>
  </div>

<div class="modal fade" id="modal-add" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="modalCenterTitle">New License</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form action="{!! route('admin.license.create') !!}" method="post" id="form-create">
                @csrf
                <div class="modal-body">
                    <div class="input-group mb-3">
                        <input type="text" class="form-control" placeholder="LICENSE-XXX-XXX-XXX" autocomplete="off" name="license_key">
                        <button class="btn btn-outline-primary waves-effect btn-generate-key" type="button">Generate</button>
                    </div>
                    <div class="mb-3">
                        <label for="">Type</label>
                        <select class="form-select" name="item">
                            <option value="digital-product" selected>Digital Product</option>
                        </select>
                    </div>
                    <div id="item_display">
                        <label for="">Item</label>
                        <select name="item_id" class="select2 form-select form-select-lg" data-allow-clear="true">
                            @foreach ($products as $product)
                                <option value="{{ $product->id }}">{{ $product->title }}</option>
                            @endforeach
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-label-secondary" data-bs-dismiss="modal">
                        Close
                    </button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
    </div>
</div>
@endsection

@push('js')
    <script src="{!! asset('assets/dash') !!}/vendor/libs/select2/select2.js"></script>
    <script src="{!! asset('assets/dash') !!}/vendor/libs/bootstrap-select/bootstrap-select.js"></script>
    <script src="{!! asset('assets/dash') !!}/js/forms-selects.js"></script>
    <script src="{!! asset('assets/dash') !!}/vendor/libs/datatables-bs5/datatables-bootstrap5.js"></script>
    <script src="{!! asset('assets/dash/ilsya.tables.js?v=1') !!}"></script>
    <script>
        $(function () {
            const table = new itables({
                table: '.ilsya-datatables',
                ajax: '{!! route('admin.license.json') !!}',
                url_delete: '{!! route('admin.license.destroy') !!}',
                columns: [
                    { data: '' },
                    { data: 'id' },
                    { data: 'id' },
                    { data: 'license_key' },
                    { data: 'item' },
                    { data: 'item_id' },
                    { data: 'expires_at' }
                ],
                header: 'List License',
                buttons: [
                    {
                        text: '<i class="ti ti-trash me-sm-1" style="margin-top: -3px;"></i> <span class="d-none d-sm-inline-block">Delete</span>',
                        className: 'itable-btn-delete btn btn-label-danger me-2'
                    },
                    {
                        text: '<i class="ti ti-plus me-sm-1"></i> <span class="d-none d-sm-inline-block">Add New</span>',
                        className: 'btn btn-primary me-2',
                        attr: {
                            'data-bs-toggle': 'modal',
                            'data-bs-target': '#modal-add'
                        }
                    },
                ]
            });



            $("#form-create").on('submit',function(e){
                e.preventDefault();
                $("#form-create button[type='submit']").attr('disabled',true);
                $.ajax({
                    url: $(this).attr('action'),
                    type: 'POST',
                    headers: {
                        'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content'),
                    },
                    data: $(this).serialize(),
                    success: function (data) {
                        Swal.fire({
                            icon: 'success',
                            text: data.message ?? 'License created successfully!',
                            showConfirmButton: false,
                            timer: 1500
                        })
                        $("#modal-add").modal('hide');
                        table.ajax.reload();
                        $("#form-create button[type='submit']").attr('disabled',false);
                        $("#form-create input[name='license_key']").val('');
                    },
                    error: function (data) {
                        $("#form-create button[type='submit']").attr('disabled',false);
                        Swal.fire({
                            icon: 'error',
                            text: data.responseJSON.message ?? 'Something went wrong!',
                            showConfirmButton: false,
                            timer: 1500
                        });
                    }
                });
            });

            $(".btn-generate-key").on('click',function(){
                $.ajax({
                    url: '{!! route('admin.license.generate.key') !!}',
                    type: 'POST',
                    headers: {
                        'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content'),
                    },
                    data: { type : $("select[name='item']").val() },
                    success: function (data) {
                        if(!data) {
                            Swal.fire({
                                icon: 'info',
                                text: 'Something went wrong!',
                                showConfirmButton: false,
                                timer: 1500
                            });
                        }
                        $("input[name='license_key']").val(data);
                    },
                    error: function (data) {
                        Swal.fire({
                            icon: 'error',
                            text: data.responseJSON.message ?? 'Something went wrong!',
                            showConfirmButton: false,
                            timer: 1500
                        });
                    }
                });
            })
        });
    </script>
@endpush

@push('css')
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/datatables-bs5/datatables.bootstrap5.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/datatables-responsive-bs5/responsive.bootstrap5.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/datatables-checkboxes-jquery/datatables.checkboxes.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/datatables-buttons-bs5/buttons.bootstrap5.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/flatpickr/flatpickr.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/datatables-rowgroup-bs5/rowgroup.bootstrap5.css" />

    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/select2/select2.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/bootstrap-select/bootstrap-select.css" />
@endpush
