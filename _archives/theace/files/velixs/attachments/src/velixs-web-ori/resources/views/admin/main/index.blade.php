@extends('layouts.admin.main')

@section('title', 'Dashboards')

@section('content')
<div class="row">
    <div class="col-xl-4 mb-4 col-lg-5 col-12">
        <div class="card"  style="height: 159px !important">
            <div class="d-flex align-items-end row">
                <div class="col-7">
                    <div class="card-body text-nowrap">
                        <h5 class="card-title mb-0">Welcome {{ $auth->name }} 🎉</h5>
                        <p class="mb-2">AdminPanel</p>
                        <div id="btn-quick-what">

                        </div>
                    </div>
                </div>
                <div class="col-5 text-center text-sm-left">
                    <div class="card-body px-md-4">
                        <img src="{!! $ws->_logo() !!}" height="100" alt="view sales">
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col">
        <div class="card">
            <div class="card-header">
                <div class="d-flex justify-content-between mb-3">
                    <h5 class="card-title mb-0">Statistics</h5>
                    <small class="text-muted">Updated 1 secound ago</small>
                </div>
            </div>
            <div class="card-body">
                <div class="row gy-3">
                    <div class="col-md-3 col-6">
                        <div class="d-flex align-items-center">
                            <div class="badge rounded-pill bg-label-primary me-3 p-2">
                                <i class="ti ti-file-dollar ti-sm" style="margin-top: -3px"></i>
                            </div>
                            <div class="card-info">
                                <h5 class="mb-0">{{ $count_product }}</h5>
                                <small>Products</small>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 col-6">
                        <div class="d-flex align-items-center">
                            <div class="badge rounded-pill bg-label-info me-3 p-2">
                                <svg xmlns="http://www.w3.org/2000/svg" width="19" height="19" viewBox="0 0 24 24" stroke-width="1" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                                    <path d="M8 21h8a5 5 0 0 0 5 -5v-3a3 3 0 0 0 -3 -3h-1v-2a5 5 0 0 0 -5 -5h-4a5 5 0 0 0 -5 5v8a5 5 0 0 0 5 5z"></path>
                                    <path d="M7 7m0 1.5a1.5 1.5 0 0 1 1.5 -1.5h3a1.5 1.5 0 0 1 1.5 1.5v0a1.5 1.5 0 0 1 -1.5 1.5h-3a1.5 1.5 0 0 1 -1.5 -1.5z"></path>
                                    <path d="M7 14m0 1.5a1.5 1.5 0 0 1 1.5 -1.5h7a1.5 1.5 0 0 1 1.5 1.5v0a1.5 1.5 0 0 1 -1.5 1.5h-7a1.5 1.5 0 0 1 -1.5 -1.5z"></path>
                                 </svg>
                            </div>
                            <div class="card-info">
                                <h5 class="mb-0">{{ $count_blog }}</h5>
                                <small>Blogs</small>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 col-6">
                        <div class="d-flex align-items-center">
                            <div class="badge rounded-pill bg-label-danger me-3 p-2">
                                <i class="ti ti-shopping-cart ti-sm"></i>
                            </div>
                            <div class="card-info">
                                <h5 class="mb-0">{{ $count_purchases }}</h5>
                                <small>License</small>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 col-6">
                        <div class="d-flex align-items-center">
                            <div class="badge rounded-pill bg-label-success me-3 p-2">
                                <i class="ti ti-users ti-sm"></i>
                            </div>
                            <div class="card-info">
                                <h5 class="mb-0">{{ $count_users }}</h5>
                                <small>Users</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<div class="col-12 mb-4">
    <div class="card">
      <div class="card-header d-flex justify-content-between">
        <div>
          <h5 class="card-title mb-0">Last updates</h5>
          <small class="text-muted">Commercial networks</small>
        </div>
        <div class="dropdown">
          <button
            type="button"
            class="btn dropdown-toggle px-0"
            data-bs-toggle="dropdown"
            aria-expanded="false"
          >
            <i class="ti ti-calendar"></i>
          </button>
          <ul class="dropdown-menu dropdown-menu-end">
            <li>
              <a href="javascript:void(0);" class="dropdown-item d-flex align-items-center">Today</a>
            </li>
            <li>
              <a href="javascript:void(0);" class="dropdown-item d-flex align-items-center">Yesterday</a>
            </li>
            <li>
              <a href="javascript:void(0);" class="dropdown-item d-flex align-items-center"
                >Last 7 Days</a
              >
            </li>
            <li>
              <a href="javascript:void(0);" class="dropdown-item d-flex align-items-center"
                >Last 30 Days</a
              >
            </li>
            <li>
              <hr class="dropdown-divider" />
            </li>
            <li>
              <a href="javascript:void(0);" class="dropdown-item d-flex align-items-center"
                >Current Month</a
              >
            </li>
            <li>
              <a href="javascript:void(0);" class="dropdown-item d-flex align-items-center">Last Month</a>
            </li>
          </ul>
        </div>
      </div>
      <div class="card-body">
        <div id="lineAreaChart"></div>
      </div>
    </div>
</div>
<div class="row">
    <div class="col-xl-4 mb-4">
        <div class="card" style="height: 506px;">
            <div class="card-header d-flex justify-content-between">
                <div class="card-title m-0 me-2">
                    <h5 class="m-0 me-2">Browser States</h5>
                    <small class="text-muted">Counter Every Time</small>
                </div>
                <div class="dropdown">
                    <button class="btn p-0" type="button" id="employeeList" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        <i class="ti ti-dots-vertical ti-sm text-muted"></i>
                    </button>
                </div>
            </div>
            <div class="card-body">
                <ul class="p-0 m-0">
                    @foreach ($browsers as $browser)
                        <li class="d-flex mb-4 pb-1">

                            <div class="d-flex w-100 align-items-center gap-2" style="position: relative;">
                                <div class="d-flex justify-content-between flex-grow-1 flex-wrap">
                                    @switch($browser->browser_group)
                                        @case('Chrome')
                                            <div class="d-flex align-items-center">
                                                <img src="{!! asset('assets/dash/img/brands/chrome.png') !!}" alt="Chrome" height="28" class="me-3 rounded">
                                                <h6 class="mb-0">Google Chrome</h6>
                                            </div>
                                            @break
                                        @case('Safari')
                                            <div class="d-flex align-items-center">
                                                <img src="{!! asset('assets/dash/img/brands/safari.png') !!}" alt="Chrome" height="28" class="me-3 rounded">
                                                <h6 class="mb-0">Safari</h6>
                                            </div>
                                            @break
                                        @case('Mozilla')
                                            <div class="d-flex align-items-center">
                                                <img src="{!! asset('assets/dash/img/brands/firefox.png') !!}" alt="Chrome" height="28" class="me-3 rounded">
                                                <h6 class="mb-0">Mozilla</h6>
                                            </div>
                                            @break
                                        @case('Edge')
                                            <div class="d-flex align-items-center">
                                                <img src="{!! asset('assets/dash/img/brands/edge.png') !!}" alt="Chrome" height="28" class="me-3 rounded">
                                                <h6 class="mb-0">Edge</h6>
                                            </div>
                                            @break
                                        @case('Opera')
                                            <div class="d-flex align-items-center">
                                                <img src="{!! asset('assets/dash/img/brands/opera.png') !!}" alt="Chrome" height="28" class="me-3 rounded">
                                                <h6 class="mb-0">Opera</h6>
                                            </div>
                                            @break
                                        @default
                                        <div class="d-flex align-items-center">
                                            <img src="{!! asset('assets/dash/img/brands/internet.png') !!}" alt="Chrome" height="28" class="me-3 rounded">
                                            <h6 class="mb-0">Other</h6>
                                        </div>
                                    @endswitch

                                    <div class="user-progress d-flex align-items-center gap-2">
                                        {{-- 100.00 to 100% --}}
                                        <h6 class="mb-0">
                                            {{ number_format($browser->percentage, 0) . '%'; }}
                                        </h6>
                                    </div>
                                </div>
                            </div>
                        </li>
                    @endforeach
                </ul>
            </div>
        </div>
    </div>
    <div class="col-xl-8">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <div>
                    <p class="card-subtitle text-muted mb-1">Countery Percentage</p>
                </div>
            </div>
            <div class="card-body">
                <div id="horizontalBarChart"></div>
            </div>
        </div>
    </div>
</div>
<div class="row">
    <div class="col-12">
        <div class="card">
            <h5 class="card-header">Referral</h5>
            <div class="table-responsive text-nowrap">
                <table class="table">
                    <thead>
                        <tr class="text-nowrap">
                            <th>#</th>
                            <th>Url</th>
                            <th>Visitor</th>
                            <th>Percentage</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ($page_views as $index=>$pageview)
                            <tr>
                                <th scope="row">{{$index+1}}</th>
                                <td>{{$pageview->referral}}</td>
                                <td>{{ $pageview->total }}</td>
                                <td>{{ $pageview->percentage }}%</td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
@endsection

@push('js')
<script src="{!! asset('assets/dash') !!}/vendor/libs/apex-charts/apexcharts.js"></script>
<script>
    var btn = [
            '<a href="{!! route('admin.license.index') !!}" class="btn btn-label-primary waves-effect waves-light">Manage License ?</a>',
            '<a href="{!! route('admin.product.index') !!}" class="btn btn-label-warning waves-effect waves-light">Manage Products ?</a>',
            '<a href="{!! route('admin.blog.index') !!}" class="btn btn-label-info waves-effect waves-light">Manage Blogs ?</a>',
        ]
    $('#btn-quick-what').html(btn[0])
    var index = 1;
    setInterval(function() {
        $('#btn-quick-what').html(btn[index++])
        if (index >= btn.length) {
            index = 0;
        }
    }, 2000)

    let cardColor, headingColor, labelColor, borderColor, legendColor;

    if (isDarkStyle) {
        cardColor = config.colors_dark.cardColor;
        headingColor = config.colors_dark.headingColor;
        labelColor = config.colors_dark.textMuted;
        legendColor = config.colors_dark.bodyColor;
        borderColor = config.colors_dark.borderColor;
    } else {
        cardColor = config.colors.cardColor;
        headingColor = config.colors.headingColor;
        labelColor = config.colors.textMuted;
        legendColor = config.colors.bodyColor;
        borderColor = config.colors.borderColor;
    }

    new ApexCharts(document.querySelector('#horizontalBarChart'), {
      chart: {
        height: 400,
        type: 'bar',
        toolbar: {
          show: false
        }
      },
      plotOptions: {
        bar: {
          horizontal: true,
          barHeight: '30%',
          startingShape: 'rounded',
          borderRadius: 8
        },
      },
      grid: {
        borderColor: borderColor,
        xaxis: {
          lines: {
            show: false
          }
        },
        padding: {
          top: -20,
          bottom: -12
        }
      },
      colors: config.colors.info,
      dataLabels: {
        enabled: true,
        formatter: function (val) {
            return val + "%";
        },
        position: 'end'
      },
      series: [
        {
          name: 'Percentage',
          data: {!! json_encode($counterys['percentage'] ?? []) !!}

        }
      ],
      xaxis: {
        categories: {!! json_encode($counterys['name'] ?? []) !!},
        axisBorder: {
          show: false
        },
        axisTicks: {
          show: false
        },
        labels: {
          style: {
            colors: labelColor,
            fontSize: '13px'
          }
        }
      },
      yaxis: {
        labels: {
          style: {
            colors: labelColor,
            fontSize: '13px'
          }
        }
      }
    }).render();

    new ApexCharts(document.querySelector('#lineAreaChart'), {
      chart: {
        height: 400,
        type: 'area',
        parentHeightOffset: 0,
        toolbar: {
          show: false
        }
      },
      dataLabels: {
        enabled: false
      },
      stroke: {
        show: false,
        curve: 'straight'
      },
      grid: {
        borderColor: borderColor,
        xaxis: {
          lines: {
            show: false
          }
        }
      },
      colors: ['#29dac7'],
      series: [
        {
          name: '{{ $month['display']['current'] }} (now)',
          data: {!! json_encode($month['total']) !!}
        }
      ],
      xaxis: {
        categories: {!! json_encode($month['month']) !!},
        axisBorder: {
          show: false
        },
        axisTicks: {
          show: false
        },
        labels: {
          style: {
            colors: labelColor,
            fontSize: '13px'
          }
        }
      },
      yaxis: {
        labels: {
          style: {
            colors: labelColor,
            fontSize: '13px'
          }
        }
      },
      fill: {
        opacity: 1,
        type: 'solid'
      },
      tooltip: {
        shared: false
      }
    }).render();
</script>
@endpush

@push('css')
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/apex-charts/apex-charts.css" />
@endpush
