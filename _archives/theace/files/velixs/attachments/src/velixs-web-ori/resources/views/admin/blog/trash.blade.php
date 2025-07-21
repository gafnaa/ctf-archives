@extends('layouts.admin.main')

@section('title', 'Trash Blogs')

@section('content')
<div class="card">
    <div class="card-datatable table-responsive pt-0">
      <table class="ilsya-datatables table">
        <thead>
          <tr>
            <th></th>
            <th></th>
            <th>id</th>
            <th>Name</th>
            <th>visitor</th>
            <th>deleted_at</th>
            <th>Action</th>
          </tr>
        </thead>
      </table>
    </div>
  </div>
@endsection

@push('js')
    <script src="{!! asset('assets/dash') !!}/vendor/libs/datatables-bs5/datatables-bootstrap5.js"></script>
    <script src="{!! asset('assets/dash/ilsya.tables.js?v=1') !!}"></script>
    <script>
        $(function () {
            const table = new itables({
                table: '.ilsya-datatables',
                ajax: '{!! route('admin.blog.json',["type" => $type]) !!}',
                url_delete: '{!! route('admin.blog.destroy.force') !!}',
                columns: [
                    { data: '' },
                    { data: 'id' },
                    { data: 'id' },
                    { data: 'title' },
                    { data: 'view' },
                    { data: 'deleted_at' },
                    { data: '' }
                ],
                header: 'Trash Blogs',
                buttons: [
                    {
                        text: '<i class="ti ti-trash me-sm-1" style="margin-top: -3px;"></i> <span class="d-none d-sm-inline-block">Force Delete</span>',
                        className: 'itable-btn-delete btn btn-label-danger me-2'
                    },
                    {
                        text: '<i class="ti ti-arrow-back-up me-sm-1" style="margin-top: -3px;"></i> <span class="d-none d-sm-inline-block">Back Products</span>',
                        className: 'btn btn-primary me-2',
                        action: function () {
                            window.location.href = "{!! route('admin.blog.index') !!}";
                        }
                    },
                ],
                customDefs: [
                    {
                        targets: -1,
                        title: 'Actions',
                        orderable: false,
                        searchable: false,
                        render: function (data, type, full, meta) {
                            return ('<a href="javascript:void(0)" data-id="'+ full.id +'" class="btn btn-sm btn-warning itable-btn-recovery">Recovery</a>');
                        }
                    }
                ],
            });

            //itable btn recovery
            table.on('click', '.itable-btn-recovery', function (e) {
                e.preventDefault();
                const id = $(this).data('id');
                Swal.fire({
                    html: '<div class="d-flex justify-content-center"><div class="sk-bounce sk-primary"><div class="sk-bounce-dot"></div><div class="sk-bounce-dot"></div></div></div><br>Loading...',
                    allowOutsideClick: false,
                    buttonsStyling: false,
                    showConfirmButton: false,
                });
                $.ajax({
                    url: '{!! route('admin.blog.trash.recovery','') !!}'+"/"+id,
                    type: 'GET',
                    success: function (data) {
                        table.ajax.reload();
                        Swal.fire({
                            icon: 'success',
                            text: data.message ?? 'Data successfully recovered.',
                            customClass: {
                                confirmButton: 'btn btn-success'
                            },
                            timer: 1500
                        });
                    },
                    error: function (data) {
                        Swal.fire({
                            icon: 'error',
                            text: data.responseJSON.message ?? 'Something went wrong!',
                            customClass: {
                                confirmButton: 'btn btn-success'
                            },
                            timer: 1500
                        });
                    }
                });
            });
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
@endpush
