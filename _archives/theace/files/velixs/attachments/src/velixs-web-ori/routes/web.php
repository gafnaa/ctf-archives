<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\BlogController;
use App\Http\Controllers\DashboardsController;
use App\Http\Controllers\DashReferralController;
use App\Http\Controllers\MainController;
use App\Http\Controllers\ProductController;
use App\Http\Controllers\RapiController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::get('/', [MainController::class, 'index'])->name('main');
Route::get('/contact', [MainController::class, 'contact'])->name('contact');
Route::get('/search', [MainController::class, 'search'])->name('search.axios');
Route::get('/sitemap.xml', [MainController::class, 'sitemap'])->name('sitemap')->withoutMiddleware('web');
Route::get('/whatsapp-programmer', [MainController::class, 'whatsappProgrammer'])->name('whatsapp.programmer');
Route::post('/whatsapp-programmer', [MainController::class, 'whatsappProgrammer'])->name('whatsapp.programmer.submit');
Route::get('pricing', [MainController::class, 'pricing'])->name('pricing');

Route::get('/terms-of-service', [MainController::class, 'tos'])->name('tos');
Route::get('/privacy-policy', [MainController::class, 'privacy'])->name('privacy');

Route::get('/sus',[MainController::class, 'sus'])->name('sus');

// auth routes start
Route::get('login',[AuthController::class, 'index'])->name('login')->middleware('guest');
Route::post('login',[AuthController::class, 'index'])->name('login')->middleware('guest');
Route::get('register',[AuthController::class, 'register'])->name('register')->middleware('guest');
Route::post('register',[AuthController::class, 'register'])->name('register')->middleware('guest');
// Route::get('register',[AuthController::class, 'register_v2'])->name('register')->middleware('guest');
// Route::post('register',[AuthController::class, 'register_v2'])->name('register')->middleware('guest');
Route::get('register/welcome',[AuthController::class, 'register_welcome'])->name('register.welcome');
Route::get('logout',[AuthController::class, 'logout'])->name('logout')->middleware('auth');
Route::get('forgot',[AuthController::class, 'forgot'])->name('forgot')->middleware('guest');
Route::post('forgot',[AuthController::class, 'forgot'])->name('forgot')->middleware('guest');
Route::get('reset-password/{token}',[AuthController::class, 'reset'])->name('password.reset')->middleware('guest');
Route::post('reset-password',[AuthController::class, 'resetpost'])->name('password.update')->middleware('guest');
// auth routes end

Route::group([
    'prefix' => 'blog',
],function(){
    Route::get('/',[BlogController::class, 'index'])->name('blog');
    Route::get('/t/{sort}',[BlogController::class, 'index'])->name('blog.sort');
    Route::get('/{slug}',[BlogController::class, 'show'])->name('blog.detail');

    Route::post('/react',[BlogController::class, 'react'])->name('blog.react.axios');
});

Route::group([
    'prefix' => 'item',
],function(){
    Route::get('/',[ProductController::class, 'index'])->name('product');
    Route::get('/claim/{slug}',[ProductController::class, 'claim'])->name('product.claim_library.axios')->middleware('auth.suspended');
    Route::get('/sort/{sort}',[ProductController::class, 'index'])->name('product.sort');
    Route::get('/{slug}',[ProductController::class, 'show'])->name('product.detail');
    Route::get('/wishlist/{slug}',[ProductController::class, 'toggle_wishlist'])->name('product.axios.toggle.wishlist')->middleware('auth.suspended');
});

Route::group([
    'prefix' => 'dash',
    'middleware' => ['auth','auth.suspended']
],function(){
    Route::get('/',[DashboardsController::class, 'index'])->name('dash');
    Route::get('/personal', [DashboardsController::class, 'personal'])->name('dash.personal');
    Route::post('/personal/update', [DashboardsController::class, 'personal'])->name('dash.personal.axios.update');
    Route::post('/personal/avatar', [DashboardsController::class, 'update_avatar'])->name('dash.personal.axios.avatar');
    Route::get('/personal/toggle-private', [DashboardsController::class, 'personal_toggle_private'])->name('dash.personal.axios.toggle-private');
    Route::get('/security', [DashboardsController::class, 'security'])->name('dash.security');
    Route::post('/security/update', [DashboardsController::class, 'security'])->name('dash.security.axios.update');

    // digital products
    Route::get('/purchases', [DashboardsController::class, 'purchases'])->name('dash.purchases');
    Route::get('/getdownload/dp/{id}', [DashboardsController::class, 'getdownloadDproduct'])->name('dash.getdownload.axio.dp');

    Route::get('/wishlist', [DashboardsController::class, 'wishlist'])->name('dash.wishlist');

    Route::get('/license/{license}', [DashboardsController::class, 'claimLicense'])->name('dash.license');

    Route::get('/apihub', [DashboardsController::class, 'apihub'])->name('dash.apihub');
    Route::get('/apihub/generate-apikey', [DashboardsController::class, 'apihub_generateapikey'])->name('dash.apihub.generateapikey.ajax');
    Route::get('/apihub/plan-info', [DashboardsController::class, 'apihub_planinfo'])->name('dash.apihub.planinfo.ajax');

    Route::get('/referral', [DashReferralController::class, 'index'])->name('dash.referral');
    Route::get('/referral/transaction/axios', [DashReferralController::class, 'getTransaction'])->name('dash.referral.transaction.axios');
    Route::post('/referral/withdraw', [DashReferralController::class, 'withdraw'])->name('dash.referral.withdraw');
});

Route::group([
    'prefix' => 'rapi',
], function(){
    Route::get('/', [RapiController::class, 'index'])->name('rapi');
    Route::get('/hub', [RapiController::class, 'explore'])->name('rapi.hub');
    Route::get('/{slug}', [RapiController::class, 'detail'])->name('rapi.detail');
    Route::get('/{slug}/lab', [RapiController::class, 'detail'])->name('rapi.lab');
});

Route::get('/@VELIXS-{license}', [MainController::class, 'license_direct'])->name('license.direct');
Route::get('/@{username}', [MainController::class, 'profile'])->name('profile');
// admin routes start
require_once __DIR__ . '/admin.php';
