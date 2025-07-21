<!DOCTYPE html>

<html
  lang="en"
  class="light-style layout-navbar-fixed layout-menu-fixed"
  dir="ltr"
  data-theme="theme-default"
  data-assets-path="{{ asset('assets/dash') }}/"
  data-template="vertical-menu-template"
>
  <head>
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no, minimum-scale=1.0, maximum-scale=1.0" />

    <title>ADMIN - @yield('title')</title>

    <meta name="robots" content="noindex, nofollow" />

    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Public+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;1,300;1,400;1,500;1,600;1,700&display=swap" rel="stylesheet" />
    {{-- <link rel="stylesheet" href="{{ asset('assets/dash') }}/vendor/fonts/fontawesome.css" /> --}}
    <link rel="stylesheet" href="{{ asset('assets/dash') }}/vendor/fonts/tabler-icons.css" />
    <link rel="stylesheet" href="{{ asset('assets/dash') }}/vendor/css/rtl/core.css" class="template-customizer-core-css" />
    <link rel="stylesheet" href="{{ asset('assets/dash') }}/vendor/css/rtl/theme-default.css" class="template-customizer-theme-css" />
    <link rel="stylesheet" href="{{ asset('assets/dash') }}/css/demo.css" />
    <link rel="stylesheet" href="{{ asset('assets/dash') }}/vendor/libs/perfect-scrollbar/perfect-scrollbar.css" />
    <link rel="stylesheet" href="{{ asset('assets/dash') }}/vendor/libs/node-waves/node-waves.css" />
    <link rel="stylesheet" href="{{ asset('assets/dash') }}/vendor/libs/typeahead-js/typeahead.css" />
    <link rel="stylesheet" href="{{ asset('assets/dash') }}/vendor/libs/animate-css/animate.css" />
    <link rel="stylesheet" href="{{ asset('assets/dash') }}/vendor/libs/sweetalert2/sweetalert2.css" />
    <link rel="stylesheet" href="{{ asset('assets/dash') }}/vendor/libs/spinkit/spinkit.css" />
    @stack('css')
    <script src="{{ asset('assets/dash') }}/vendor/js/helpers.js"></script>
    <script src="{{ asset('assets/dash') }}/vendor/js/template-customizer.js"></script>
    <script src="{{ asset('assets/dash') }}/js/config.js"></script>
  </head>

  <body>
    <!-- Layout wrapper -->
    <div class="layout-wrapper layout-content-navbar">
      <div class="layout-container">
        <!-- Menu -->

        <aside id="layout-menu" class="layout-menu menu-vertical menu bg-menu-theme">
          <div class="app-brand demo">
            <a href="index.html" class="app-brand-link">
              <span class="app-brand-logo demo">
                <img src="{!! asset('assets/img/logo.svg') !!}" alt="">
              </span>
              <span class="app-brand-text demo menu-text fw-bold">AdminPanel</span>
            </a>

            <a href="javascript:void(0);" class="layout-menu-toggle menu-link text-large ms-auto">
              <i class="ti menu-toggle-icon d-none d-xl-block ti-sm align-middle"></i>
              <i class="ti ti-x d-block d-xl-none ti-sm align-middle"></i>
            </a>
          </div>

          <div class="menu-inner-shadow"></div>

          <ul class="menu-inner py-1">
            <li class="menu-item {{ Route::is('admin.index') ? 'active' : '' }}">
                <a href="{!! route('admin.index') !!}" class="menu-link">
                    <i class="menu-icon tf-icons ti ti-home"></i>
                    <div data-i18n="Main Dashboards">Main Dashboards</div>
                </a>
            </li>
            <li class="menu-header small text-uppercase">
              <span class="menu-header-text">Content</span>
            </li>
            <li class="menu-item {{ Route::is('admin.product*') ? 'active open' : '' }}">
              <a href="javascript:void(0);" class="menu-link menu-toggle">
                <svg xmlns="http://www.w3.org/2000/svg" class="menu-icon tf-icons" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                    <path d="M3 5a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v14a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-14z"></path>
                    <path d="M9 17h-2"></path>
                    <path d="M13 12h-6"></path>
                    <path d="M11 7h-4"></path>
                </svg>
                <div data-i18n="Products">Products</div>
              </a>
              <ul class="menu-sub">
                <li class="menu-item {{ Route::is('admin.product.index') ? 'active' : '' }}">
                  <a href="{!! route('admin.product.index') !!}" class="menu-link">
                    <div data-i18n="Manage Product">Manage Product</div>
                  </a>
                </li>
                <li class="menu-item {{ Route::is('admin.product.create') ? 'active' : '' }}">
                  <a href="{!! route('admin.product.create') !!}" class="menu-link">
                    <div data-i18n="New Product">New Product</div>
                  </a>
                </li>
                <li class="menu-item {{ Route::is('admin.product.tags') ? 'active' : '' }}">
                  <a href="{!! route('admin.product.tags') !!}" class="menu-link">
                    <div data-i18n="Manage Category">Manage Category</div>
                  </a>
                </li>
              </ul>
            </li>
            <li class="menu-item {{ Route::is('admin.blog*') ? 'active open' : '' }}">
              <a href="javascript:void(0);" class="menu-link menu-toggle">
                <svg xmlns="http://www.w3.org/2000/svg" class="menu-icon tf-icons" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                    <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                    <path d="M8 21h8a5 5 0 0 0 5 -5v-3a3 3 0 0 0 -3 -3h-1v-2a5 5 0 0 0 -5 -5h-4a5 5 0 0 0 -5 5v8a5 5 0 0 0 5 5z"></path>
                    <path d="M7 7m0 1.5a1.5 1.5 0 0 1 1.5 -1.5h3a1.5 1.5 0 0 1 1.5 1.5v0a1.5 1.5 0 0 1 -1.5 1.5h-3a1.5 1.5 0 0 1 -1.5 -1.5z"></path>
                    <path d="M7 14m0 1.5a1.5 1.5 0 0 1 1.5 -1.5h7a1.5 1.5 0 0 1 1.5 1.5v0a1.5 1.5 0 0 1 -1.5 1.5h-7a1.5 1.5 0 0 1 -1.5 -1.5z"></path>
                 </svg>
                <div data-i18n="Blogs">Blogs</div>
              </a>
              <ul class="menu-sub">
                <li class="menu-item {{ Route::is('admin.blog.index') ? 'active' : '' }}">
                  <a href="{!! route('admin.blog.index') !!}" class="menu-link">
                    <div data-i18n="Manage Blog">Manage Blog</div>
                  </a>
                </li>
                <li class="menu-item {{ Route::is('admin.blog.create') ? 'active' : '' }}">
                  <a href="{!! route('admin.blog.create') !!}" class="menu-link">
                    <div data-i18n="New Blog">New Blog</div>
                  </a>
                </li>
                <li class="menu-item {{ Route::is('admin.blog.tags') ? 'active' : '' }}">
                  <a href="{!! route('admin.blog.tags') !!}" class="menu-link">
                    <div data-i18n="Manage Category">Manage Category</div>
                  </a>
                </li>
              </ul>
            </li>
            <li class="menu-item {{ Route::is('admin.rapi*') ? 'active open' : '' }} {{ Route::is('admin.plan*') ? 'active open' : '' }}">
                <a href="javascript:void(0);" class="menu-link menu-toggle">
                   <svg xmlns="http://www.w3.org/2000/svg" class="menu-icon tf-icons" viewBox="0 0 24 24" stroke-width="1.8" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                        <path d="M12 12c2 -2.96 0 -7 -1 -8c0 3.038 -1.773 4.741 -3 6c-1.226 1.26 -2 3.24 -2 5a6 6 0 1 0 12 0c0 -1.532 -1.056 -3.94 -2 -5c-1.786 3 -2.791 3 -4 2z"></path>
                    </svg>
                  <div data-i18n="API HUB">API HUB</div>
                </a>
                <ul class="menu-sub">
                  <li class="menu-item {{ Route::is('admin.rapi.index') ? 'active' : '' }}">
                    <a href="{!! route('admin.rapi.index') !!}" class="menu-link">
                      <div data-i18n="Manage APIs">Manage APIs</div>
                    </a>
                  </li>
                  <li class="menu-item {{ Route::is('admin.plan.index') ? 'active' : '' }}">
                    <a href="{!! route('admin.plan.index') !!}" class="menu-link">
                      <div data-i18n="Manage Plan">Manage Plan</div>
                    </a>
                  </li>
                </ul>
            </li>
            <li class="menu-header small text-uppercase">
                <span class="menu-header-text">Management</span>
            </li>
            <li class="menu-item {{ Route::is('admin.license.index') ? 'active' : '' }}">
              <a href="{!! route('admin.license.index') !!}" class="menu-link">
                <i class="menu-icon tf-icons ti ti-hash"></i>
                <div data-i18n="Manage License">Manage License</div>
              </a>
            </li>
            <li class="menu-item {{ Route::is('admin.license.purchases') ? 'active' : '' }}">
              <a href="{!! route('admin.license.purchases') !!}" class="menu-link">
                <i class="menu-icon tf-icons ti ti-wallet"></i>
                <div data-i18n="Manage Purchases">Manage Purchases</div>
              </a>
            </li>
            <li class="menu-item {{ Route::is('admin.users.*') ? 'active' : '' }}">
              <a href="{!! route('admin.users.index') !!}" class="menu-link">
                <i class="menu-icon tf-icons ti ti-users"></i>
                <div data-i18n="Manage Users">Manage Users</div>
              </a>
            </li>
            <li class="menu-item {{ Route::is('admin.wagroup.index') ? 'active' : '' }}">
              <a href="{!! route('admin.wagroup.index') !!}" class="menu-link">
                <i class="menu-icon tf-icons ti ti-brand-whatsapp"></i>
                <div data-i18n="Manage Users">Manage WAGroup</div>
              </a>
            </li>
            <li class="menu-item {{ Route::is('admin.ref*') ? 'active open' : '' }} {{ Route::is('admin.plan*') ? 'active open' : '' }}">
                <a href="javascript:void(0);" class="menu-link menu-toggle">
                    <svg xmlns="http://www.w3.org/2000/svg" class="menu-icon tf-icons" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                        <path d="M6 5h12l3 5l-8.5 9.5a.7 .7 0 0 1 -1 0l-8.5 -9.5l3 -5"></path>
                        <path d="M10 12l-2 -2.2l.6 -1"></path>
                    </svg>
                  <div data-i18n="Manage Rest APi">Manage Referral</div>
                </a>
                <ul class="menu-sub">
                  <li class="menu-item">
                    <a href="{!! route('admin.ref.index') !!}" class="menu-link">
                      <div data-i18n="Referral Earnings">Referral Earnings</div>
                    </a>
                  </li>
                  <li class="menu-item">
                    <a href="{!! route('admin.ref.index', ['type'=>'withdraw']) !!}" class="menu-link">
                      <div data-i18n="Request Withdraw">Request Withdraw</div>
                    </a>
                  </li>
                </ul>
            </li>

            <li class="menu-header small text-uppercase">
                <span class="menu-header-text">Other</span>
            </li>
            <li class="menu-item {{ Route::is('admin.files.index') ? 'active' : '' }}">
                <a href="{!! route('admin.files.index') !!}" class="menu-link">
                    <i class="menu-icon tf-icons ti ti-folder"></i>
                    <div data-i18n="Files Manager">Files Manager</div>
                </a>
            </li>
            <li class="menu-item {{ Route::is('admin.settings') ? 'active' : '' }}">
                <a href="{!! route('admin.settings') !!}" class="menu-link">
                    <i class="menu-icon tf-icons ti ti-settings"></i>
                    <div data-i18n="Web Settings">Web Settings</div>
                </a>
            </li>
          </ul>
        </aside>
        <!-- / Menu -->

        <!-- Layout container -->
        <div class="layout-page">
          <!-- Navbar -->

          <nav class="layout-navbar container-xxl navbar navbar-expand-xl navbar-detached align-items-center bg-navbar-theme" id="layout-navbar" >
            <div class="layout-menu-toggle navbar-nav align-items-xl-center me-3 me-xl-0 d-xl-none">
              <a class="nav-item nav-link px-0 me-xl-4" href="javascript:void(0)">
                <i class="ti ti-menu-2 ti-sm"></i>
              </a>
            </div>

            <div class="navbar-nav-right d-flex align-items-center" id="navbar-collapse">
              <!-- Search -->
              <div class="navbar-nav align-items-center">
                <div class="nav-item navbar-search-wrapper mb-0">
                  <a class="nav-item nav-link search-toggler d-flex align-items-center px-0" href="javascript:void(0);">
                    <i class="ti ti-search ti-md me-2"></i>
                    <span class="d-none d-md-inline-block text-muted">Search (Ctrl+/)</span>
                  </a>
                </div>
              </div>
              <!-- /Search -->

              <ul class="navbar-nav flex-row align-items-center ms-auto">

                <!-- Style Switcher -->
                <li class="nav-item me-2 me-xl-0">
                  <a class="nav-link style-switcher-toggle hide-arrow" href="javascript:void(0);">
                    <i class="ti ti-md"></i>
                  </a>
                </li>
                <!--/ Style Switcher -->

                <!-- Quick links  -->
                <li class="nav-item dropdown-shortcuts navbar-dropdown dropdown me-2 me-xl-0">
                  <a
                    class="nav-link dropdown-toggle hide-arrow"
                    href="javascript:void(0);"
                    data-bs-toggle="dropdown"
                    data-bs-auto-close="outside"
                    aria-expanded="false"
                  >
                    <i class="ti ti-layout-grid-add ti-md"></i>
                  </a>
                  <div class="dropdown-menu dropdown-menu-end py-0">
                    <div class="dropdown-menu-header border-bottom">
                      <div class="dropdown-header d-flex align-items-center py-3">
                        <h5 class="text-body mb-0 me-auto">Shortcuts</h5>
                        <a
                          href="javascript:void(0)"
                          class="dropdown-shortcuts-add text-body"
                          data-bs-toggle="tooltip"
                          data-bs-placement="top"
                          title="Add shortcuts"
                          ><i class="ti ti-sm ti-apps"></i
                        ></a>
                      </div>
                    </div>
                    <div class="dropdown-shortcuts-list scrollable-container">
                      <div class="row row-bordered overflow-visible g-0">
                        <div class="dropdown-shortcuts-item col">
                          <span class="dropdown-shortcuts-icon rounded-circle mb-2">
                            <i class="ti ti-home fs-4"></i>
                          </span>
                          <a href="{!! route('main') !!}" class="stretched-link">Landing</a>
                          <small class="text-muted mb-0">Back to landing</small>
                        </div>
                        <div class="dropdown-shortcuts-item col">
                          <span class="dropdown-shortcuts-icon rounded-circle mb-2">
                            <i class="ti ti-file-invoice fs-4"></i>
                          </span>
                          <a href="{!! route('dash') !!}" class="stretched-link">Dashboards</a>
                          <small class="text-muted mb-0">Go to dashboard user.</small>
                        </div>
                      </div>
                    <div class="dropdown-shortcuts-list scrollable-container">
                      <div class="row row-bordered overflow-visible g-0">
                        <div class="dropdown-shortcuts-item col">
                          <span class="dropdown-shortcuts-icon rounded-circle mb-2">
                            <i class="ti ti-code fs-4"></i>
                          </span>
                          <a href="javascript:void(0)" class="stretched-link btn-generate-sitemap">Generate Sitemap</a>
                          <small class="text-muted mb-0">Update Sitemp</small>
                        </div>
                      </div>
                    </div>
                  </div>
                </li>
                <!-- Quick links -->

                <!-- Notification -->
                <li class="nav-item dropdown-notifications navbar-dropdown dropdown me-3 me-xl-1">
                  <a
                    class="nav-link dropdown-toggle hide-arrow"
                    href="javascript:void(0);"
                    data-bs-toggle="dropdown"
                    data-bs-auto-close="outside"
                    aria-expanded="false"
                  >
                    <i class="ti ti-bell ti-md"></i>
                    <span class="badge bg-danger rounded-pill badge-notifications">0</span>
                  </a>
                  <ul class="dropdown-menu dropdown-menu-end py-0">
                    <li class="dropdown-menu-header border-bottom">
                      <div class="dropdown-header d-flex align-items-center py-3">
                        <h5 class="text-body mb-0 me-auto">Notification</h5>
                        <a
                          href="javascript:void(0)"
                          class="dropdown-notifications-all text-body"
                          data-bs-toggle="tooltip"
                          data-bs-placement="top"
                          title="Mark all as read"
                          ><i class="ti ti-mail-opened fs-4"></i
                        ></a>
                      </div>
                    </li>
                    <li class="dropdown-notifications-list scrollable-container">
                      <ul class="list-group list-group-flush">
                      </ul>
                    </li>
                    <li class="dropdown-menu-footer border-top">
                      <a
                        href="javascript:void(0);"
                        class="dropdown-item d-flex justify-content-center text-primary p-2 h-px-40 mb-1 align-items-center"
                      >
                        View all notifications
                      </a>
                    </li>
                  </ul>
                </li>
                <!--/ Notification -->

                <!-- User -->
                <li class="nav-item navbar-dropdown dropdown-user dropdown">
                  <a class="nav-link dropdown-toggle hide-arrow" href="javascript:void(0);" data-bs-toggle="dropdown">
                    <div class="avatar avatar-online">
                      <img src="{!! $auth->_avatar() !!}" alt class="h-auto rounded-circle" />
                    </div>
                  </a>
                  <ul class="dropdown-menu dropdown-menu-end">
                    <li>
                      <a class="dropdown-item" href="{!! route('profile',$auth->username) !!}">
                        <div class="d-flex">
                          <div class="flex-shrink-0 me-3">
                            <div class="avatar avatar-online">
                              <img src="{!! $auth->_avatar() !!}" alt class="h-auto rounded-circle" />
                            </div>
                          </div>
                          <div class="flex-grow-1">
                            <span class="fw-semibold d-block">{{ $auth->name }}</span>
                            <small class="text-muted">{{ "@".$auth->username }}</small>
                          </div>
                        </div>
                      </a>
                    </li>
                    <li>
                      <div class="dropdown-divider"></div>
                    </li>
                    <li>
                      <a class="dropdown-item" href="{!! route('profile',$auth->username) !!}">
                        <i class="ti ti-user-check me-2 ti-sm"></i>
                        <span class="align-middle">My Profile</span>
                      </a>
                    </li>
                    <li>
                      <a class="dropdown-item" href="{!! route('dash.personal') !!}">
                        <i class="ti ti-settings me-2 ti-sm"></i>
                        <span class="align-middle">Settings</span>
                      </a>
                    </li>
                    <li>
                      <div class="dropdown-divider"></div>
                    </li>
                    <li>
                      <a class="dropdown-item" href="{!! route('logout') !!}">
                        <i class="ti ti-logout me-2 ti-sm"></i>
                        <span class="align-middle">Log Out</span>
                      </a>
                    </li>
                  </ul>
                </li>
                <!--/ User -->
              </ul>
            </div>

            <!-- Search Small Screens -->
            <div class="navbar-search-wrapper search-input-wrapper d-none">
              <input
                type="text"
                class="form-control search-input container-xxl border-0"
                placeholder="Search..."
                aria-label="Search..."
              />
              <i class="ti ti-x ti-sm search-toggler cursor-pointer"></i>
            </div>
          </nav>

          <div class="content-wrapper">

            <div class="container-xxl flex-grow-1 container-p-y">
                @yield('content')
            </div>

            <div class="content-backdrop fade"></div>
          </div>
        </div>
      </div>
      <div class="layout-overlay layout-menu-toggle"></div>
      <div class="drag-target"></div>
    </div>

    <script src="{{ asset('assets/dash') }}/vendor/libs/jquery/jquery.js"></script>
    <script src="{{ asset('assets/dash') }}/vendor/libs/popper/popper.js"></script>
    <script src="{{ asset('assets/dash') }}/vendor/js/bootstrap.js"></script>
    <script src="{{ asset('assets/dash') }}/vendor/libs/perfect-scrollbar/perfect-scrollbar.js"></script>
    <script src="{{ asset('assets/dash') }}/vendor/libs/node-waves/node-waves.js"></script>
    <script src="{{ asset('assets/dash') }}/vendor/libs/hammer/hammer.js"></script>
    <script src="{{ asset('assets/dash') }}/vendor/libs/i18n/i18n.js"></script>
    <script src="{{ asset('assets/dash') }}/vendor/libs/typeahead-js/typeahead.js"></script>
    <script src="{{ asset('assets/dash') }}/vendor/js/menu.js"></script>
    <script src="{{ asset('assets/dash') }}/js/main.js"></script>
    <script src="{{ asset('assets/dash') }}/vendor/libs/sweetalert2/sweetalert2.js"></script>
    <script>
        @if (session()->has('info'))
            Swal.fire({
                text: "{{ session('info') }}",
                icon: "info",
                buttonsStyling: false,
                confirmButtonText: "Ok",
                timer: 3000,
                customClass: {
                    confirmButton: "btn btn-label-primary"
                }
            });
        @elseif (session()->has('success'))
            Swal.fire({
                text: "{{ session('success') }}",
                icon: "success",
                buttonsStyling: false,
                confirmButtonText: "Ok",
                timer: 3000,
                customClass: {
                    confirmButton: "btn btn-label-primary"
                }
            });
        @elseif (session()->has('warning'))
            Swal.fire({
                text: "{{ session('warning') }}",
                icon: "warning",
                buttonsStyling: false,
                confirmButtonText: "Ok",
                timer: 3000,
                customClass: {
                    confirmButton: "btn btn-label-primary"
                }
            });
        @elseif (session()->has('error'))
            Swal.fire({
                text: "{{ session('error') }}",
                icon: "error",
                buttonsStyling: false,
                confirmButtonText: "Ok",
                timer: 3000,
                customClass: {
                    confirmButton: "btn btn-label-primary"
                }
            });
        @endif

        @if ($errors->any())
            @foreach ($errors->all() as $error)
                Swal.fire({
                    text: "{{ $error }}",
                    icon: "error",
                    buttonsStyling: false,
                    confirmButtonText: "Ok",
                    timer: 3000,
                    customClass: {
                        confirmButton: "btn btn-label-primary"
                    }
                });
            @endforeach
        @endif

        $(document).on('click', '.btn-generate-sitemap', function(e){
            e.preventDefault();
            $(this).attr('disabled', true).text('Loading...');
            $.ajax({
                url: "{!! route('admin.settings.generate.sitemap') !!}",
                type: "GET",
                success: function(response) {
                    Swal.fire({
                        icon: "success",
                        text: response.message ?? "Sitemap generated successfully",
                        showConfirmButton: false,
                        timer: 1500,
                    });
                    $(".btn-generate-sitemap").removeAttr("disabled").text("Generate SiteMap");
                },
                error: function(xhr) {
                    Swal.fire({
                        icon: "error",
                        text: xhr.responseJSON.message ?? "Something went wrong",
                        showConfirmButton: false,
                        timer: 1500,
                    });
                    $(".btn-generate-sitemap").removeAttr("disabled").text("Generate SiteMap");
                },
            });
        })
    </script>
    @stack('js')
  </body>
</html>
