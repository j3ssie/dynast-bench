<?php

use App\Http\Controllers\AdminController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\BillingController;
use App\Http\Controllers\CommentController;
use App\Http\Controllers\PostController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\ReportController;
use App\Http\Controllers\ToolsController;
use App\Http\Controllers\VerifyController;
use Illuminate\Support\Facades\Route;

Route::get('/', fn () => view('home'));

// --- auth (pre-auth) ---
Route::get('/login', [AuthController::class, 'showLogin'])->name('login');
Route::post('/login', [AuthController::class, 'login']);
Route::post('/logout', [AuthController::class, 'logout']);
Route::get('/register', [AuthController::class, 'showRegister']);
Route::post('/register', [AuthController::class, 'register']);
Route::post('/password/email', [AuthController::class, 'sendReset']);
Route::post('/password/reset', [AuthController::class, 'doReset']);

// --- public tools & search (pre-auth surface) ---
Route::get('/search', [PostController::class, 'search']);
Route::get('/tools/fetch', [ToolsController::class, 'fetch']);
Route::get('/tools/download', [ToolsController::class, 'download']);
Route::get('/tools/export', [ToolsController::class, 'export']);
Route::get('/tools/preview', [ToolsController::class, 'preview']);
Route::get('/go', [ToolsController::class, 'go']);
Route::get('/diagnostics', [ToolsController::class, 'diagnostics']);

// --- authenticated app ---
Route::middleware('auth')->group(function () {
    Route::get('/dashboard', fn () => view('dashboard'));

    Route::get('/posts', [PostController::class, 'index']);
    Route::post('/posts', [PostController::class, 'store']);
    Route::get('/posts/{post}', [PostController::class, 'show']);
    Route::get('/posts/{post}/audit', [PostController::class, 'audit']); // NM-IDOR-001
    Route::post('/posts/{post}/comments', [CommentController::class, 'store']);

    Route::get('/profile', [ProfileController::class, 'show']);
    Route::post('/profile', [ProfileController::class, 'update']);          // MASSASSIGN-001
    Route::post('/profile/avatar', [ProfileController::class, 'avatar']);   // UPLOAD-001
    Route::post('/account/name', [ProfileController::class, 'rename']);     // CSRF-001 (exempt)

    Route::get('/admin/users', [AdminController::class, 'users']);          // AUTHZ-001 (no admin gate)
    Route::get('/admin/audit', [AdminController::class, 'audit'])->middleware('admin'); // NM-AUTHZ-001

    Route::post('/tools/import', [ToolsController::class, 'import']);       // DESER-001
    Route::get('/reports/titles', [ReportController::class, 'titles']);     // SQLI-002 (second-order)

    Route::get('/billing', [BillingController::class, 'status']);
    Route::post('/billing/topup', [BillingController::class, 'topup']);     // BILLING-001
    Route::post('/billing/invite', [BillingController::class, 'invite']);   // RACE-001
});

// --- harness-only verification API (guarded by X-Verify-Token) ---
Route::get('/api/_verify/health', [VerifyController::class, 'health']);
Route::get('/api/_verify/user', [VerifyController::class, 'user']);
Route::get('/api/_verify/post', [VerifyController::class, 'post']);
