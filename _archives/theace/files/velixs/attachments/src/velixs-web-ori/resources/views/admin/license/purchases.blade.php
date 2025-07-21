@extends('layouts.admin.main')

@section('title', 'Manage Purchases')

@section('content')
<div class="card">
    <div class="card-datatable table-responsive pt-0">
      <table class="ilsya-datatables table">
        <thead>
          <tr>
            <th></th>
            <th></th>
            <th>id</th>
            <th>item</th>
            <th>type</th>
            <th>key</th>
            <th>owner</th>
            <th>expires at</th>
            <th>created_at</th>
          </tr>
        </thead>
      </table>
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
                ajax: '{!! route('admin.license.purchases.json',[
                    'user' => request()->get('user'),
                ]) !!}',
                url_delete: '{!! route('admin.license.purchases.destroy') !!}',
                columns: [
                    { data: '' },
                    { data: 'id' },
                    { data: 'id' },
                    { data: 'item_id' },
                    { data: 'item' },
                    { data: 'license_key' },
                    { data: 'user' },
                    { data: 'expires_at' },
                    { data: 'created_at' }
                ],
                header: 'List Purchases',
                buttons: [
                    {
                        text: '<i class="ti ti-trash me-sm-1" style="margin-top: -3px;"></i> <span class="d-none d-sm-inline-block">Delete</span>',
                        className: 'itable-btn-delete btn btn-label-danger me-2'
                    },
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

    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/select2/select2.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/bootstrap-select/bootstrap-select.css" />
@endpush
