var a78_0x4b8d = [
    '23711kAtmOK',
    '156703rThZRx',
    '339726HhwWAR',
    '19KbzyZL',
    'asyncMatchers',
    'toBePending',
    '887qEMqTs',
    '88dlbWio',
    'objectContaining',
    'fails\x20if\x20the\x20actual\x20promise\x20is\x20rejected',
    '555RzzNmA',
    '16285INdFJI',
    'reject',
    'getEnv',
    '488144bnCUYE',
    'promise\x20was\x20rejected',
    'requirePromises',
    'passes\x20if\x20the\x20actual\x20promise\x20is\x20pending',
    'toEqual',
    'MatchersUtil',
    'then',
    'fails\x20if\x20actual\x20is\x20not\x20a\x20promise',
    'compare',
    '14CDkgtR',
    '10059ROQZiM'
];
function a78_0x20f9(_0x155f63, _0x5e0d36) {
    return a78_0x20f9 = function (_0x4b8dc9, _0x20f9c3) {
        _0x4b8dc9 = _0x4b8dc9 - 0x1cf;
        var _0x398d88 = a78_0x4b8d[_0x4b8dc9];
        return _0x398d88;
    }, a78_0x20f9(_0x155f63, _0x5e0d36);
}
var a78_0x12ac36 = a78_0x20f9;
(function (_0x1e37ec, _0x20235d) {
    var _0xf41364 = a78_0x20f9;
    while (!![]) {
        try {
            var _0xc0d6bb = parseInt(_0xf41364(0x1e6)) * parseInt(_0xf41364(0x1d1)) + parseInt(_0xf41364(0x1e2)) + -parseInt(_0xf41364(0x1d5)) + parseInt(_0xf41364(0x1e1)) + parseInt(_0xf41364(0x1de)) * parseInt(_0xf41364(0x1d2)) + parseInt(_0xf41364(0x1e0)) * parseInt(_0xf41364(0x1e3)) + -parseInt(_0xf41364(0x1e7)) * parseInt(_0xf41364(0x1df));
            if (_0xc0d6bb === _0x20235d)
                break;
            else
                _0x1e37ec['push'](_0x1e37ec['shift']());
        } catch (_0x3b52e7) {
            _0x1e37ec['push'](_0x1e37ec['shift']());
        }
    }
}(a78_0x4b8d, 0x47bf5), describe(a78_0x12ac36(0x1e5), function () {
    var _0x240083 = a78_0x12ac36;
    it(_0x240083(0x1d8), function () {
        var _0x5bb02b = _0x240083;
        jasmine[_0x5bb02b(0x1d4)]()['requirePromises']();
        var _0xcc34c0 = new jasmineUnderTest[(_0x5bb02b(0x1da))](), _0x46ce96 = jasmineUnderTest['asyncMatchers']['toBePending'](_0xcc34c0), _0x43bb85 = new Promise(function () {
            });
        return _0x46ce96[_0x5bb02b(0x1dd)](_0x43bb85)[_0x5bb02b(0x1db)](function (_0x47fc65) {
            var _0xf9cc23 = _0x5bb02b;
            expect(_0x47fc65)[_0xf9cc23(0x1d9)](jasmine[_0xf9cc23(0x1cf)]({ 'pass': !![] }));
        });
    }), it('fails\x20if\x20the\x20actual\x20promise\x20is\x20resolved', function () {
        var _0x11dae3 = _0x240083;
        jasmine['getEnv']()[_0x11dae3(0x1d7)]();
        var _0x11721d = new jasmineUnderTest[(_0x11dae3(0x1da))](), _0xac27c6 = jasmineUnderTest['asyncMatchers']['toBePending'](_0x11721d), _0x552d83 = Promise['resolve']();
        return _0xac27c6[_0x11dae3(0x1dd)](_0x552d83)[_0x11dae3(0x1db)](function (_0x5b05a1) {
            var _0x3bd262 = _0x11dae3;
            expect(_0x5b05a1)[_0x3bd262(0x1d9)](jasmine['objectContaining']({ 'pass': ![] }));
        });
    }), it(_0x240083(0x1d0), function () {
        var _0x5088fe = _0x240083;
        jasmine['getEnv']()[_0x5088fe(0x1d7)]();
        var _0x2e5a53 = new jasmineUnderTest['MatchersUtil'](), _0x3dce04 = jasmineUnderTest[_0x5088fe(0x1e4)][_0x5088fe(0x1e5)](_0x2e5a53), _0x59dd85 = Promise[_0x5088fe(0x1d3)](new Error(_0x5088fe(0x1d6)));
        return _0x3dce04[_0x5088fe(0x1dd)](_0x59dd85)['then'](function (_0x3bafdc) {
            var _0x20a381 = _0x5088fe;
            expect(_0x3bafdc)[_0x20a381(0x1d9)](jasmine['objectContaining']({ 'pass': ![] }));
        });
    }), it(_0x240083(0x1dc), function () {
        var _0x669634 = _0x240083, _0x17ed52 = new jasmineUnderTest['MatchersUtil'](), _0x5daec0 = jasmineUnderTest[_0x669634(0x1e4)][_0x669634(0x1e5)](_0x17ed52), _0x4b1cb0 = 'not\x20a\x20promise';
        function _0x1c620c() {
            var _0x5115b9 = _0x669634;
            return _0x5daec0[_0x5115b9(0x1dd)](_0x4b1cb0);
        }
        expect(_0x1c620c)['toThrowError']('Expected\x20toBePending\x20to\x20be\x20called\x20on\x20a\x20promise.');
    });
}));