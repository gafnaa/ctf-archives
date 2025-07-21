<?php

use App\Http\Controllers\Admin\ABlogController;
use App\Http\Controllers\Admin\ApihubController;
use App\Http\Controllers\Admin\AProductController;
use App\Http\Controllers\Admin\FilesController;
use App\Http\Controllers\Admin\LicenseController;
use App\Http\Controllers\Admin\MainController;
use App\Http\Controllers\Admin\OtherController;
use App\Http\Controllers\Admin\RefController;
use App\Http\Controllers\Admin\UsersController;
use App\Http\Controllers\Admin\WAProgrammerController;
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

Route::group([
    'prefix' => 'admin',
    'middleware' => ['isadmin']
],function(){
    Route::get('/', [MainController::class, 'index'])->name('admin.index');

    Route::prefix('product')->group(function () {
        Route::get('/',[AProductController::class, 'index'])->name('admin.product.index');
        Route::get('/trash',[AProductController::class, 'trash'])->name('admin.product.trash');
        Route::get('/trash/recovery/{id}',[AProductController::class, 'trash_recovery'])->name('admin.product.trash.recovery');
        Route::get('/json',[AProductController::class, 'json'])->name('admin.product.json');
        Route::post('/destroy',[AProductController::class, 'destroy'])->name('admin.product.destroy');
        Route::post('/destroy/force',[AProductController::class, 'destroy_force'])->name('admin.product.destroy.force');

        Route::get('/create', [AProductController::class, 'create'])->name('admin.product.create');
        Route::post('/store', [AProductController::class, 'store'])->name('admin.product.store');
        Route::get('/edit/{id}', [AProductController::class, 'edit'])->name('admin.product.edit');
        Route::post('/update/{id}', [AProductController::class, 'update'])->name('admin.product.update');

        Route::get('/release/{id}', [AProductController::class, 'release'])->name('admin.product.release');
        Route::post('/release/{id}', [AProductController::class, 'release_update'])->name('admin.product.release.update');
        Route::get('/release/force/{id}', [AProductController::class, 'release_force'])->name('admin.product.release.force');

        Route::get('/tags',[AProductController::class, 'tags_index'])->name('admin.product.tags');
        Route::get('/tags/json',[AProductController::class, 'tags_index'])->name('admin.product.tags.json');
        Route::post('/tags/create',[AProductController::class, 'tags_create'])->name('admin.product.tags.create');
        Route::post('/tags/destroy',[AProductController::class, 'tags_destroy'])->name('admin.product.tags.destroy');
        Route::get('/tags/edit/{id}',[AProductController::class, 'tags_edit'])->name('admin.product.tags.edit');
        Route::post('/tags/update',[AProductController::class, 'tags_update'])->name('admin.product.tags.update');
    });

    Route::prefix('blog')->group(function () {
        Route::get('/',[ABlogController::class, 'index'])->name('admin.blog.index');
        Route::get('/trash',[ABlogController::class, 'trash'])->name('admin.blog.trash');
        Route::get('/trash/recovery/{id}',[ABlogController::class, 'trash_recovery'])->name('admin.blog.trash.recovery');
        Route::get('/json',[ABlogController::class, 'json'])->name('admin.blog.json');
        Route::post('/destroy',[ABlogController::class, 'destroy'])->name('admin.blog.destroy');
        Route::post('/destroy/force',[ABlogController::class, 'destroy_force'])->name('admin.blog.destroy.force');

        Route::get('/create', [ABlogController::class, 'create'])->name('admin.blog.create');
        Route::post('/store', [ABlogController::class, 'store'])->name('admin.blog.store');
        Route::get('/edit/{id}', [ABlogController::class, 'edit'])->name('admin.blog.edit');
        Route::post('/update/{id}', [ABlogController::class, 'update'])->name('admin.blog.update');

        Route::get('/tags',[ABlogController::class, 'tags_index'])->name('admin.blog.tags');
        Route::get('/tags/json',[ABlogController::class, 'tags_index'])->name('admin.blog.tags.json');
        Route::post('/tags/create',[ABlogController::class, 'tags_create'])->name('admin.blog.tags.create');
        Route::post('/tags/destroy',[ABlogController::class, 'tags_destroy'])->name('admin.blog.tags.destroy');
        Route::get('/tags/edit/{id}',[ABlogController::class, 'tags_edit'])->name('admin.blog.tags.edit');
        Route::post('/tags/update',[ABlogController::class, 'tags_update'])->name('admin.blog.tags.update');
    });

    Route::prefix('license')->group(function(){
        Route::get('/',[LicenseController::class, 'index'])->name('admin.license.index');
        Route::get('/json',[LicenseController::class, 'json'])->name('admin.license.json');
        Route::post('/ajax/generate-license-key',[LicenseController::class, 'generate_license_key'])->name('admin.license.generate.key');
        Route::post('/create',[LicenseController::class, 'create'])->name('admin.license.create');
        Route::post('/destroy',[LicenseController::class, 'destroy'])->name('admin.license.destroy');

        Route::get('/purchases',[LicenseController::class, 'purchases'])->name('admin.license.purchases');
        Route::get('/purchases/json',[LicenseController::class, 'purchases_json'])->name('admin.license.purchases.json');
        Route::post('/purchases/destroy',[LicenseController::class, 'purchases_destroy'])->name('admin.license.purchases.destroy');
    });

    Route::prefix('wagroup')->group(function(){
        Route::get('/',[WAProgrammerController::class, 'index'])->name('admin.wagroup.index');
        Route::get('/json',[WAProgrammerController::class, 'json'])->name('admin.wagroup.json');
        Route::post('/toggle-status',[WAProgrammerController::class, 'toggle_status'])->name('admin.wagroup.toggle.status')->withoutMiddleware(['csrf']);
        Route::post('/destroy',[WAProgrammerController::class, 'destroy'])->name('admin.wagroup.destroy');
        Route::get('/sync',[WAProgrammerController::class, 'sync'])->name('admin.wagroup.sync');
    });

    Route::prefix('rapi')->group(function(){
        Route::get('/',[ApihubController::class, 'index'])->name('admin.rapi.index');
        Route::get('/json',[ApihubController::class, 'json'])->name('admin.rapi.json');
        Route::get('/generate-slug/ajax',[ApihubController::class, 'ajax_gslug_unique'])->name('admin.rapi.gslug.ajax');
        Route::get('/create',[ApihubController::class, 'create'])->name('admin.rapi.create');
        Route::post('/store',[ApihubController::class, 'store'])->name('admin.rapi.store');
        Route::get('/edit/{id}',[ApihubController::class, 'edit'])->name('admin.rapi.edit');
        Route::get('/syncthumb/{id}',[ApihubController::class, 'syncThumbnail'])->name('admin.rapi.syncthumb');
        Route::post('/update/{id}',[ApihubController::class, 'update'])->name('admin.rapi.update');
        Route::post('/destroy',[ApihubController::class, 'destroy'])->name('admin.rapi.destroy');

        Route::get('/{id}/endpoint',[ApihubController::class, 'ep'])->name('admin.rapi.endpoint');
        Route::get('/{id}/endpoint/json',[ApihubController::class, 'ep_json'])->name('admin.rapi.endpoint.json');
        Route::get('/{id}/endpoint/create',[ApihubController::class, 'ep_create'])->name('admin.rapi.endpoint.create');
        Route::post('/{id}/endpoint/store',[ApihubController::class, 'ep_store'])->name('admin.rapi.endpoint.store');
        Route::get('/{id}/endpoint/edit/{epid}',[ApihubController::class, 'ep_edit'])->name('admin.rapi.endpoint.edit');
        Route::post('/{id}/endpoint/update/{epid}',[ApihubController::class, 'ep_update'])->name('admin.rapi.endpoint.update');
        Route::post('/{id}/endpoint/destroy',[ApihubController::class, 'ep_destroy'])->name('admin.rapi.endpoint.destroy');
    });

    Route::prefix('plan')->group(function(){
        Route::get('/',[ApihubController::class, 'plan_index'])->name('admin.plan.index');
        Route::get('/create',[ApihubController::class, 'plan_create'])->name('admin.plan.create');
        Route::post('/create',[ApihubController::class, 'plan_create'])->name('admin.plan.create');
        Route::get('/edit/{id}',[ApihubController::class, 'plan_edit'])->name('admin.plan.edit');
        Route::post('/edit/{id}',[ApihubController::class, 'plan_edit'])->name('admin.plan.edit');
        Route::post('/delete',[ApihubController::class, 'plan_delete'])->name('admin.plan.delete');
    });

    Route::prefix('users')->group(function(){
        Route::get('/', [UsersController::class, 'index'])->name('admin.users.index');
        Route::get('/json', [UsersController::class, 'json'])->name('admin.users.json');
        Route::post('/destroy', [UsersController::class, 'destroy'])->name('admin.users.destroy');
        Route::get('/edit/{id}', [UsersController::class, 'edit'])->name('admin.users.edit');
        Route::post('/update/{id}', [UsersController::class, 'update'])->name('admin.users.update');
        Route::get('/plan/{id}', [UsersController::class, 'changePlan'])->name('admin.users.plan');
        Route::post('/plan/{id}', [UsersController::class, 'changePlan'])->name('admin.users.plan');
    });

    Route::get('/settings', [OtherController::class, 'settings'])->name('admin.settings');
    Route::post('/settings/update/meta', [OtherController::class, 'settings_meta'])->name('admin.settings.update.meta');
    Route::post('/settings/update/social', [OtherController::class, 'settings_social'])->name('admin.settings.update.social');
    Route::post('/settings/update/contact', [OtherController::class, 'settings_contact'])->name('admin.settings.update.contact');
    Route::get('/settings/genereate/sitemap', [OtherController::class, 'settings_sitemap'])->name('admin.settings.generate.sitemap');

    Route::prefix('files')->group(function(){
        Route::get('/',[FilesController::class, 'index'])->name('admin.files.index');
        Route::get('/tinymce',[FilesController::class, 'fortinymce'])->name('admin.files.fortinymce');
    });

    Route::prefix('referral')->group(function(){
        Route::get('/', [RefController::class, 'index'])->name('admin.ref.index');
        Route::get('/json', [RefController::class, 'index'])->name('admin.ref.json');
        Route::get('/edit/status/{id}', [RefController::class, 'edit_status_ajax'])->name('admin.ref.edit.status.ajax');
        Route::post('/update/status', [RefController::class, 'update_status_ajax'])->name('admin.ref.update.status.ajax');
        Route::post('/destroy', [RefController::class, 'destroy'])->name('admin.ref.destroy');
    });
});
