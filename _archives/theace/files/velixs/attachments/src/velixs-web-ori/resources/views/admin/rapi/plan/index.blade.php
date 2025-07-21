@extends('layouts.admin.main')

@section('title', 'Manage Plans')

@section('content')
<div class="card">
    <div class="card-datatable table-responsive pt-0">
      <table class="ilsya-datatables table">
        <thead>
          <tr>
            <th></th>
            <th></th>
            <th>id</th>
            <th>plan</th>
            <th>price</th>
            <th>default</th>
            <th>request / day</th>
            <th>users active</th>
            <th>action</th>
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
    <script src="{!! asset('assets/dash/ilsya.tables.js?v=112') !!}"></script>
    <script>
        $(function () {
            const table = new itables({
                table: '.ilsya-datatables',
                ajax: {
                    url : "{!! rtrim(config('app.api_velixs_endpoint'), '/').'/velixs/plan/dbs' !!}",
                    headers: {
                        "X-Secret-Key" : "{!! config('app.api_velixs_secret') !!}",
                        "X-Wow" : "{!! config('app.api_velixs_wow') !!}"
                    }
                },
                url_delete: '{!! route("admin.plan.delete") !!}',
                columns: [
                    { data: '' },
                    { data: 'id' },
                    { data: 'id' },
                    { data: 'plan' },
                    { data: 'price' },
                    { data: 'default' },
                    { data: 'max_request' },
                    { data: 'count_apikey' },
                    { data: '' }
                ],
                header: 'List Plans',
                buttons: [
                    {
                        text: '<i class="ti ti-trash me-sm-1" style="margin-top: -3px;"></i> <span class="d-none d-sm-inline-block">Delete</span>',
                        className: 'itable-btn-delete btn btn-label-danger me-2'
                    },
                    {
                        text: '<i class="ti ti-plus me-sm-1"></i> <span class="d-none d-sm-inline-block">Add New</span>',
                        className: 'btn btn-primary me-2',
                        action: function () {
                            window.location.href = '{{ route("admin.plan.create") }}';
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
                            return (
                                '<a href="{{ route("admin.plan.edit","") }}/'+full.id+'" class="btn btn-sm btn-icon item-edit itable-btn-edit"><i class="text-primary ti ti-pencil"></i></a>'
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
