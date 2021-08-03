var a195_0x5c9a = [
    'then',
    '448719eIANLD',
    '295130KVpYFc',
    'isPromiseLike',
    '348548BYJxOB',
    '1omyLgu',
    'to\x20be\x20resolved\x20to\x20',
    'Expected\x20a\x20promise\x20',
    '330503NouKmM',
    '988sYSgKw',
    '5vDOOLg',
    '86243eLvKkZ',
    '1rwgCho',
    'Expected\x20toBeResolvedTo\x20to\x20be\x20called\x20on\x20a\x20promise.',
    '154776rkhdBb',
    '3LMyLIv',
    '\x20but\x20it\x20was\x20resolved\x20to\x20'
];
function a195_0x4953(_0x8327b8, _0x336496) {
    return a195_0x4953 = function (_0x5c9a10, _0x495350) {
        _0x5c9a10 = _0x5c9a10 - 0x103;
        var _0x1d1f93 = a195_0x5c9a[_0x5c9a10];
        return _0x1d1f93;
    }, a195_0x4953(_0x8327b8, _0x336496);
}
(function (_0x45452a, _0xa117b7) {
    var _0x3815ff = a195_0x4953;
    while (!![]) {
        try {
            var _0xeb6f9d = -parseInt(_0x3815ff(0x105)) + parseInt(_0x3815ff(0x106)) * parseInt(_0x3815ff(0x109)) + parseInt(_0x3815ff(0x10f)) + parseInt(_0x3815ff(0x10a)) * parseInt(_0x3815ff(0x10b)) + parseInt(_0x3815ff(0x103)) + parseInt(_0x3815ff(0x110)) * parseInt(_0x3815ff(0x10c)) + -parseInt(_0x3815ff(0x10d)) * parseInt(_0x3815ff(0x113));
            if (_0xeb6f9d === _0xa117b7)
                break;
            else
                _0x45452a['push'](_0x45452a['shift']());
        } catch (_0x38ae43) {
            _0x45452a['push'](_0x45452a['shift']());
        }
    }
}(a195_0x5c9a, 0x3c41b), getJasmineRequireObj()['toBeResolvedTo'] = function (_0x529bd1) {
    return function _0x46f062(_0x5a4b6b) {
        return {
            'compare': function (_0x1b06d7, _0x3d7027) {
                var _0x444f2f = a195_0x4953;
                if (!_0x529bd1[_0x444f2f(0x104)](_0x1b06d7))
                    throw new Error(_0x444f2f(0x10e));
                function _0x5f213f(_0x56fb9b) {
                    var _0x512937 = _0x444f2f;
                    return _0x512937(0x108) + (_0x56fb9b ? 'not\x20' : '') + _0x512937(0x107) + _0x5a4b6b['pp'](_0x3d7027);
                }
                return _0x1b06d7[_0x444f2f(0x112)](function (_0x5aac90) {
                    var _0x2fedfa = _0x444f2f;
                    return _0x5a4b6b['equals'](_0x5aac90, _0x3d7027) ? {
                        'pass': !![],
                        'message': _0x5f213f(!![]) + '.'
                    } : {
                        'pass': ![],
                        'message': _0x5f213f(![]) + _0x2fedfa(0x111) + _0x5a4b6b['pp'](_0x5aac90) + '.'
                    };
                }, function (_0x594385) {
                    return {
                        'pass': ![],
                        'message': _0x5f213f(![]) + '\x20but\x20it\x20was\x20rejected\x20with\x20' + _0x5a4b6b['pp'](_0x594385) + '.'
                    };
                });
            }
        };
    };
});