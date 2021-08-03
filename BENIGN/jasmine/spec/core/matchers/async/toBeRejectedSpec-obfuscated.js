var a79_0x1414 = [
    'toBeRejected',
    '7KFdIQg',
    '373TeWHpw',
    'getEnv',
    '1TgZPpk',
    '2811oRgnTV',
    'then',
    'not\x20a\x20promise',
    'toEqual',
    '3095HaZMtK',
    'fails\x20if\x20the\x20actual\x20is\x20resolved',
    '247045fUbDRO',
    '134915IlOMvI',
    'resolve',
    'fails\x20if\x20actual\x20is\x20not\x20a\x20promise',
    'objectContaining',
    'AsyncExpectationSpec\x20rejection',
    '301073oEaiaD',
    'compare',
    '1WyUTOq',
    '491SSHKfv',
    'MatchersUtil',
    '633467cDWHeC',
    '5uirIIz',
    '87991AUSmMX',
    'asyncMatchers'
];
function a79_0x3725(_0x25bbe7, _0x369162) {
    return a79_0x3725 = function (_0x1414f4, _0x3725d5) {
        _0x1414f4 = _0x1414f4 - 0x79;
        var _0x493523 = a79_0x1414[_0x1414f4];
        return _0x493523;
    }, a79_0x3725(_0x25bbe7, _0x369162);
}
var a79_0x4ce68d = a79_0x3725;
(function (_0x577657, _0x28d73f) {
    var _0x591ca3 = a79_0x3725;
    while (!![]) {
        try {
            var _0x6f4bbe = parseInt(_0x591ca3(0x8f)) * parseInt(_0x591ca3(0x8c)) + -parseInt(_0x591ca3(0x87)) * parseInt(_0x591ca3(0x8a)) + -parseInt(_0x591ca3(0x85)) * parseInt(_0x591ca3(0x92)) + -parseInt(_0x591ca3(0x88)) * parseInt(_0x591ca3(0x79)) + parseInt(_0x591ca3(0x90)) * parseInt(_0x591ca3(0x7d)) + -parseInt(_0x591ca3(0x8b)) * -parseInt(_0x591ca3(0x7f)) + parseInt(_0x591ca3(0x80));
            if (_0x6f4bbe === _0x28d73f)
                break;
            else
                _0x577657['push'](_0x577657['shift']());
        } catch (_0x57a300) {
            _0x577657['push'](_0x577657['shift']());
        }
    }
}(a79_0x1414, 0xc99ab), describe(a79_0x4ce68d(0x8e), function () {
    var _0x447cca = a79_0x4ce68d;
    it('passes\x20if\x20the\x20actual\x20is\x20rejected', function () {
        var _0x19cdde = a79_0x3725;
        jasmine[_0x19cdde(0x91)]()['requirePromises']();
        var _0x58f81 = new jasmineUnderTest['MatchersUtil'](), _0x571381 = jasmineUnderTest[_0x19cdde(0x8d)][_0x19cdde(0x8e)](_0x58f81), _0xc53b3b = Promise['reject'](_0x19cdde(0x84));
        return _0x571381[_0x19cdde(0x86)](_0xc53b3b)[_0x19cdde(0x7a)](function (_0x1e7170) {
            var _0x7b3531 = _0x19cdde;
            expect(_0x1e7170)[_0x7b3531(0x7c)](jasmine['objectContaining']({ 'pass': !![] }));
        });
    }), it(_0x447cca(0x7e), function () {
        var _0x4149cc = _0x447cca;
        jasmine[_0x4149cc(0x91)]()['requirePromises']();
        var _0x159fec = new jasmineUnderTest[(_0x4149cc(0x89))](), _0x52e6f4 = jasmineUnderTest[_0x4149cc(0x8d)]['toBeRejected'](_0x159fec), _0x511e97 = Promise[_0x4149cc(0x81)]();
        return _0x52e6f4['compare'](_0x511e97)[_0x4149cc(0x7a)](function (_0x72b7b1) {
            var _0x55cffe = _0x4149cc;
            expect(_0x72b7b1)[_0x55cffe(0x7c)](jasmine[_0x55cffe(0x83)]({ 'pass': ![] }));
        });
    }), it(_0x447cca(0x82), function () {
        var _0x3c0630 = _0x447cca, _0x197f3f = new jasmineUnderTest[(_0x3c0630(0x89))](), _0x3d183b = jasmineUnderTest['asyncMatchers'][_0x3c0630(0x8e)](_0x197f3f), _0x1aa904 = _0x3c0630(0x7b);
        function _0x199c54() {
            var _0x9f01f6 = _0x3c0630;
            return _0x3d183b[_0x9f01f6(0x86)](_0x1aa904);
        }
        expect(_0x199c54)['toThrowError']('Expected\x20toBeRejected\x20to\x20be\x20called\x20on\x20a\x20promise.');
    });
}));