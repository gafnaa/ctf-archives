@extends('layouts.admin.main')

@section('title', 'Manage Product')

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
            <th>Price</th>
            <th>Published</th>
            <th>views</th>
            <th>Updated</th>
            <th></th>
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
                ajax: '{!! route('admin.product.json',["type" => $type]) !!}',
                url_delete: '{!! route('admin.product.destroy') !!}',
                columns: [
                    { data: '' },
                    { data: 'id' },
                    { data: 'id' },
                    { data: 'title' },
                    { data: 'price' },
                    { data: 'is_published' },
                    { data: 'views' },
                    { data: 'updated_at' },
                    { data: '' }
                ],
                header: 'List Products',
                customDefs: [
                    {
                        targets: -1,
                        title: 'Actions',
                        orderable: false,
                        searchable: false,
                        render: function (data, type, full, meta) {
                            return (
                                '<div class="d-inline-block">' +
                                    '<a href="javascript:;" class="btn btn-sm btn-icon dropdown-toggle hide-arrow" data-bs-toggle="dropdown"><i class="text-primary ti ti-dots-vertical"></i></a>' +
                                    '<ul class="dropdown-menu dropdown-menu-end m-0">' +
                                        '<li><a href="{!! route('product.detail','') !!}/'+ full.slug +'" class="dropdown-item itable-btn-detail">Details</a></li>' +
                                        '<li><a href="{!! route('admin.product.release','') !!}/'+ full.id +'" class="dropdown-item itable-btn-detail">Manage Release</a></li>' +
                                    '</ul>' +
                                '</div>' +
                                '<a href="{!! route('admin.product.edit','') !!}/'+ full.id +'" class="btn btn-sm btn-icon item-edit itable-btn-edit"><i class="text-primary ti ti-pencil"></i></a>'
                            );
                        }
                    }
                ],
                buttons: [
                    {
                        text: '<i class="ti ti-trash me-sm-1" style="margin-top: -3px;"></i> <span class="d-none d-sm-inline-block">Delete</span>',
                        className: 'itable-btn-delete btn btn-label-danger me-2'
                    },
                    {
                        text: '<i class="ti ti-plus me-sm-1"></i> <span class="d-none d-sm-inline-block">Add New</span>',
                        className: 'btn btn-primary me-2',
                        action: function () { window.location.href = '{!! route('admin.product.create') !!}'; }
                    },
                    {
                        text: '<i class="ti ti-rotate-clockwise me-sm-1"></i> <span class="d-none d-sm-inline-block">Trash</span>',
                        className: 'btn btn-warning',
                        action: function () { window.location.href = '{!! route('admin.product.trash') !!}'; }
                    }
                ]
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
