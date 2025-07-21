@extends('layouts.admin.main')

@section('title', 'Manage Users')

@section('content')
<div class="card">
    <div class="card-datatable table-responsive pt-0">
      <table class="ilsya-datatables table">
        <thead>
          <tr>
            <th></th>
            <th></th>
            <th>id</th>
            <th>profile</th>
            <th>role</th>
            <th>suspended</th>
            <th>member since</th>
            <th></th>
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
    <script src="{!! asset('assets/dash/ilsya.tables.js?v=12') !!}"></script>
    <script>
        $(function () {
            const table = new itables({
                table: '.ilsya-datatables',
                ajax: '{!! route('admin.users.json') !!}',
                url_delete: '{!! route('admin.users.destroy') !!}',
                columns: [
                    { data: '' },
                    { data: 'id' },
                    { data: 'id' },
                    { data: 'profile' },
                    { data: 'role' },
                    { data: 'suspended' },
                    { data: 'created_at' },
                    { data: '' }
                ],
                header: 'List Users',
                buttons: [
                    {
                        text: '<i class="ti ti-trash me-sm-1" style="margin-top: -3px;"></i> <span class="d-none d-sm-inline-block">Delete</span>',
                        className: 'itable-btn-delete btn btn-label-danger me-2'
                    },
                ],
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
                                        '<li><a href="{!! route('admin.license.purchases') !!}?user='+full.username+'" class="dropdown-item itable-btn-detail">License Owned</a></li>' +
                                        '<li><a href="{!! route('admin.ref.index','') !!}/?user='+full.username+'" class="dropdown-item itable-btn-detail">Referral Earnings</a></li>' +
                                        '<li><a href="{!! route('admin.ref.index','') !!}/?type=withdraw&user='+full.username+'" class="dropdown-item itable-btn-detail">Referral Withdrawn</a></li>' +
                                        '<li><a href="{!! route('admin.users.plan','') !!}/'+full.id+'" class="dropdown-item itable-btn-detail">API Plan</a></li>' +
                                        '</ul>' +
                                '</div>' +
                                '<a href="{!! route('admin.users.edit','') !!}/'+ full.id +'" class="btn btn-sm btn-icon item-edit itable-btn-edit"><i class="text-primary ti ti-pencil"></i></a>'
                            );
                        }
                    }
                ],
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
