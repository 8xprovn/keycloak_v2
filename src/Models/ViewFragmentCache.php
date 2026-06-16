<?php

namespace Keycloak\Models;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class ViewFragmentCache
{
    private $defaultTtl = 300;
    private $hasUncacheableData = false;

    /**
     * Tao cache key theo route hien tai.
     * Neu khong truyen fragment thi mac dinh dung ten route.
     */
    public function key(Request $request, ?string $fragment = null, array $extra = []): string
    {
        $fragment = $fragment ?: (optional($request->route())->getName() ?: $request->path());

        return 'view_fragment:' . md5(json_encode(array_merge([
            'route' => optional($request->route())->getName(),
            'path' => $request->path(),
            'fragment' => $fragment,
        ], $extra)));
    }

    /**
     * Lay thoi gian song cua cache, don vi giay.
     * TTL truyen truc tiep duoc uu tien, sau do den attribute tu middleware, cuoi cung la mac dinh cua class.
     */
    public function seconds(Request $request, ?int $ttl = null): int
    {
        return $ttl ?? (int) $request->attributes->get('cache_view_seconds', $this->defaultTtl);
    }

    /**
     * Lay data view tu cache cho request hien tai.
     * Tra ve null khi request khong duoc cache hoac cache chua ton tai.
     */
    public function getData(Request $request, ?int $ttl = null, ?string $fragment = null, array $extra = [])
    {
        if (!$this->shouldCache($request, $ttl)) {
            return null;
        }

        return $this->restoreData(Cache::get($this->key($request, $fragment, $extra)));
    }

    /**
     * Luu data view vao cache cho request hien tai.
     * Data duoc chuan hoa truoc de tranh loi serialize voi paginator, view object hoac collection.
     */
    public function putData(Request $request, array $data, ?int $ttl = null, ?string $fragment = null, array $extra = []): bool
    {
        if (!$this->shouldCache($request, $ttl)) {
            return false;
        }

        [$data, $canCache] = $this->prepareData($data);

        if (!$canCache) {
            return false;
        }

        $seconds = $this->seconds($request, $ttl);
        Cache::put($this->key($request, $fragment, $extra), $data, $seconds);

        return true;
    }

    /**
     * Kiem tra request co duoc phep dung cache data khong.
     * Chi cache trang GET mac dinh; bo qua filter, phan trang, export va JSON.
     */
    public function shouldCache(Request $request, ?int $ttl = null): bool
    {
        return $this->seconds($request, $ttl) > 0
            && $request->isMethod('GET')
            && !$request->wantsJson()
            && !$request->headers->has('page-action')
            && $request->query->count() === 0;
    }

    /**
     * Chuyen du lieu ve dang an toan de luu cache.
     * Tranh loi serialize voi paginator, Htmlable, Collection, BSONArray hoac object co __toString().
     * Cursor/Traversable khac khong duoc cache truc tiep vi co the da iterate va khong rewind duoc.
     */
    public function normalizeData($value)
    {
        if ($value instanceof \Illuminate\Pagination\Paginator) {
            return $value->items();
        }

        if ($value instanceof \Illuminate\Contracts\Support\Htmlable) {
            return $value->toHtml();
        }

        if ($value instanceof \Illuminate\Support\Collection) {
            return $this->normalizeData($value->values()->all());
        }

        if ($value instanceof \ArrayObject) {
            return $this->normalizeData($value->getArrayCopy());
        }

        if ($value instanceof \Traversable) {
            $this->hasUncacheableData = true;
            return null;
        }

        if (is_object($value) && method_exists($value, '__toString')) {
            return (string) $value;
        }

        if (is_array($value)) {
            return array_map([$this, 'normalizeData'], $value);
        }

        return $value;
    }

    /**
     * Chuan hoa data va tra kem trang thai co duoc cache hay khong.
     * Neu gap Cursor/Traversable thi bo qua cache cho toan bo response de tranh mat/thieu data.
     */
    public function prepareData($value): array
    {
        $this->hasUncacheableData = false;
        $data = $this->normalizeData($value);

        return [$data, !$this->hasUncacheableData];
    }

    /**
     * Khoi phuc data sau khi lay tu cache.
     * Rows duoc doi lai thanh collection vi Blade hien tai dang dung cac method cua collection.
     */
    public function restoreData($data)
    {
        if (!is_array($data)) {
            return $data;
        }

        if (isset($data['rows']) && is_array($data['rows'])) {
            $data['rows'] = collect($data['rows']);
        }

        return $data;
    }
}
