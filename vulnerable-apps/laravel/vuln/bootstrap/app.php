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

        // CSRF-001 (CWE-352): a state-changing route is excluded from CSRF
        // verification, so a cross-site form can drive it. The safe twin drops
        // the exemption and the route is protected like every other POST.
        //
        // The signup and import-mapping endpoints are JSON APIs the client drives
        // with fetch (no Blade form, no cookie session for a fresh visitor), so
        // they are legitimately CSRF-exempt in BOTH twins - that exemption is not
        // the bug. The bugs on those endpoints are in their handlers.
        $middleware->validateCsrfTokens(except: [
            'account/name',
            'api/signup/*',
            'api/tools/import-mapping',
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })->create();
