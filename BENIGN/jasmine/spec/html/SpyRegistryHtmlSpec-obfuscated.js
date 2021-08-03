var a136_0x1a5a = [
    'set',
    '321917DGdmxf',
    '3331WUycKS',
    '224969gwNHIH',
    'Spy',
    'clearSpies',
    'SpyRegistry',
    'spyOn',
    'Spy\x20Registry\x20browser-specific\x20behavior',
    '189322uFdMtO',
    'can\x20spy\x20on\x20and\x20unspy\x20window.onerror',
    '1LhyEqm',
    '2iEzvlM',
    'toBe',
    '216645NOXTct',
    'onerror',
    '3617EyOqnt',
    'getOwnPropertyDescriptor',
    'Browser\x20declares\x20window.onerror\x20to\x20be\x20readonly',
    '37939bweoZj',
    '5GkUmRY',
    'writable'
];
var a136_0x100b82 = a136_0x27b3;
function a136_0x27b3(_0x49fad7, _0x5a143e) {
    return a136_0x27b3 = function (_0x1a5a41, _0x27b303) {
        _0x1a5a41 = _0x1a5a41 - 0x1db;
        var _0x26edd1 = a136_0x1a5a[_0x1a5a41];
        return _0x26edd1;
    }, a136_0x27b3(_0x49fad7, _0x5a143e);
}
(function (_0x5a44df, _0x31cb40) {
    var _0x5d4e3a = a136_0x27b3;
    while (!![]) {
        try {
            var _0x561f50 = -parseInt(_0x5d4e3a(0x1eb)) + -parseInt(_0x5d4e3a(0x1f0)) + parseInt(_0x5d4e3a(0x1df)) + -parseInt(_0x5d4e3a(0x1ee)) * parseInt(_0x5d4e3a(0x1e4)) + parseInt(_0x5d4e3a(0x1dc)) * -parseInt(_0x5d4e3a(0x1e0)) + parseInt(_0x5d4e3a(0x1e5)) + -parseInt(_0x5d4e3a(0x1ed)) * -parseInt(_0x5d4e3a(0x1e3));
            if (_0x561f50 === _0x31cb40)
                break;
            else
                _0x5a44df['push'](_0x5a44df['shift']());
        } catch (_0x8731a2) {
            _0x5a44df['push'](_0x5a44df['shift']());
        }
    }
}(a136_0x1a5a, 0x259ff), describe(a136_0x100b82(0x1ea), function () {
    var _0x4b9b5b = a136_0x100b82;
    function _0x4639b5(_0x15dd7a, _0x23a68f) {
        var _0x4149c1 = a136_0x27b3;
        return jasmineUnderTest[_0x4149c1(0x1e6)](_0x15dd7a, _0x23a68f);
    }
    it(_0x4b9b5b(0x1ec), function () {
        var _0x47596c = _0x4b9b5b;
        _0x547a9f();
        var _0x3c3762 = [], _0x3b43e7 = new jasmineUnderTest[(_0x47596c(0x1e8))]({
                'currentSpies': function () {
                    return _0x3c3762;
                },
                'createSpy': _0x4639b5,
                'global': window
            }), _0x803723 = window[_0x47596c(0x1db)];
        try {
            _0x3b43e7[_0x47596c(0x1e9)](window, _0x47596c(0x1db)), _0x3b43e7[_0x47596c(0x1e7)](), expect(window['onerror'])[_0x47596c(0x1ef)](_0x803723);
        } finally {
            window[_0x47596c(0x1db)] = _0x803723;
        }
    });
    function _0x547a9f() {
        var _0x37eef0 = _0x4b9b5b, _0x1fb9d0;
        try {
            _0x1fb9d0 = Object[_0x37eef0(0x1dd)](window, _0x37eef0(0x1db));
        } catch (_0xc157cc) {
        }
        _0x1fb9d0 && !(_0x1fb9d0[_0x37eef0(0x1e1)] || _0x1fb9d0[_0x37eef0(0x1e2)]) && pending(_0x37eef0(0x1de));
    }
}));