<?php

namespace Keycloak\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\View\View;
use Keycloak\Models\ViewFragmentCache;

class CacheViewData
{
    /**
     * Cache data cua cac response dang return view(...).
     *
     * Flow:
     * - Neu request khong du dieu kien cache thi cho chay controller binh thuong.
     * - Neu cache hit thi render lai Blade bang view name va data da luu, khong vao controller.
     * - Neu cache miss thi vao controller, lay view name + data tu response roi luu cache.
     */
    public function handle(Request $request, Closure $next, int $seconds = 300)
    {
        $viewCache = new ViewFragmentCache();

        // Chi cache GET mac dinh, khong query string, khong JSON, khong export/page-action.
        if (!$viewCache->shouldCache($request, $seconds)) {
            return $next($request);
        }

        // Tach key rieng cho middleware cache view data de khong trung voi cache data thu cong.
        $key = $viewCache->key($request, null, ['mode' => 'view_data']);

        // Cache hit: dung view name + data da luu de render lai Blade, bo qua controller va query.
        if (($cachedInfo = Cache::get($key)) !== null) {
            if (is_array($cachedInfo) && !empty($cachedInfo['view_name']) && array_key_exists('data', $cachedInfo)) {
                return response()->view(
                    $cachedInfo['view_name'],
                    $viewCache->restoreData($cachedInfo['data'])
                );
            }

            // Neu cache sai format thi xoa de request sau tu tao lai cache moi.
            Cache::forget($key);
        }

        // Cache miss: cho request vao controller de tao response goc.
        $response = $next($request);

        // Chi luu cache response thanh cong, tranh cache nham trang loi.
        if (method_exists($response, 'isSuccessful') && !$response->isSuccessful()) {
            return $response;
        }

        // Chi cache khi controller tra ve return view(...).
        // Cac response JSON, redirect, download... se bi bo qua.
        if (method_exists($response, 'getOriginalContent')) {
            $originalContent = $response->getOriginalContent();

            if ($originalContent instanceof View) {
                // Chi luu ten view va data da normalize, khong luu HTML.
                [$data, $canCache] = $viewCache->prepareData($originalContent->getData());

                if (!$canCache) {
                    // Mot so data nhu Mongo cursor khong the cache an toan.
                    // Khi gap case do thi bo qua cache, nhung van tra response goc cho user.
                    return $response;
                }

                Cache::put($key, [
                    'view_name' => $originalContent->getName(),
                    'data' => $data,
                ], $viewCache->seconds($request, $seconds));
            }
        }

        return $response;
    }
}
