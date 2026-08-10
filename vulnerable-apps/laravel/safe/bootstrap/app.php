<?php

use App\Http\Middleware\AdminOnly;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->alias([
            'admin' => AdminOnly::class,
        ]);

        // FIXED CSRF-001: the account/name exemption is gone - that route is
        // protected like every other Blade POST. The signup and import-mapping
        // endpoints stay exempt in BOTH twins: they are fetch-driven JSON APIs
        // with no form token, and that exemption is not the bug (the bugs on
        // those endpoints are in their handlers).
        $middleware->validateCsrfTokens(except: [
            'api/signup/*',
            'api/tools/import-mapping',
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })->create();
