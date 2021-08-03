var a115_0x5a85 = [
    'toThrowError',
    '279791uHnpTq',
    'message',
    'createSpy',
    '88211XIsuDV',
    'matchers',
    'passes\x20if\x20what\x20is\x20thrown\x20is\x20equivalent\x20to\x20what\x20is\x20expected',
    'compare',
    'toBe',
    '1hGBNGn',
    '10nAcGmJ',
    '25952RtefUW',
    '239569dWWNUO',
    'and',
    'toEqual',
    'fails\x20if\x20what\x20is\x20thrown\x20is\x20not\x20equivalent\x20to\x20what\x20is\x20expected',
    'Expected\x20function\x20to\x20throw\x20undefined,\x20but\x20it\x20threw\x205.',
    'toThrow',
    'fails\x20if\x20actual\x20does\x20not\x20throw',
    'Expected\x20function\x20not\x20to\x20throw,\x20but\x20it\x20threw\x20undefined.',
    '4Gynlbu',
    '14215OkUbBh',
    '160433dPoQKN',
    '10642uNamdh',
    'foo',
    'throws\x20an\x20error\x20when\x20the\x20actual\x20is\x20not\x20a\x20function',
    'makePrettyPrinter',
    'delegated-equal',
    'returnValue',
    'Expected\x20function\x20to\x20throw\x20an\x20exception.',
    '17PBLjpt',
    'passes\x20if\x20it\x20throws\x20but\x20there\x20is\x20no\x20expected',
    'Expected\x20function\x20to\x20throw\x20\x27foo\x27,\x20but\x20it\x20threw\x205.',
    'pass'
];
var a115_0x1052fd = a115_0xb31b;
function a115_0xb31b(_0x14a19c, _0x1bffb6) {
    return a115_0xb31b = function (_0x5a85b7, _0xb31b3d) {
        _0x5a85b7 = _0x5a85b7 - 0x1a1;
        var _0x3fe3db = a115_0x5a85[_0x5a85b7];
        return _0x3fe3db;
    }, a115_0xb31b(_0x14a19c, _0x1bffb6);
}
(function (_0x2d8b16, _0x1d3eb5) {
    var _0x2f4ff5 = a115_0xb31b;
    while (!![]) {
        try {
            var _0x2cb5ae = parseInt(_0x2f4ff5(0x1ad)) * parseInt(_0x2f4ff5(0x1ae)) + -parseInt(_0x2f4ff5(0x1c1)) * -parseInt(_0x2f4ff5(0x1ba)) + -parseInt(_0x2f4ff5(0x1a7)) + -parseInt(_0x2f4ff5(0x1b8)) * parseInt(_0x2f4ff5(0x1b7)) + parseInt(_0x2f4ff5(0x1a4)) + parseInt(_0x2f4ff5(0x1af)) * -parseInt(_0x2f4ff5(0x1ac)) + -parseInt(_0x2f4ff5(0x1b9));
            if (_0x2cb5ae === _0x1d3eb5)
                break;
            else
                _0x2d8b16['push'](_0x2d8b16['shift']());
        } catch (_0x3504ad) {
            _0x2d8b16['push'](_0x2d8b16['shift']());
        }
    }
}(a115_0x5a85, 0x2ac30), describe(a115_0x1052fd(0x1b4), function () {
    var _0x189be4 = a115_0x1052fd;
    it(_0x189be4(0x1bc), function () {
        var _0x3803c8 = _0x189be4, _0x5d598d = jasmineUnderTest[_0x3803c8(0x1a8)][_0x3803c8(0x1b4)]();
        expect(function () {
            _0x5d598d['compare']({}), matcherComparator({});
        })[_0x3803c8(0x1a3)](/Actual is not a Function/);
    }), it(_0x189be4(0x1b5), function () {
        var _0x3251b9 = _0x189be4, _0x37307e = jasmineUnderTest[_0x3251b9(0x1a8)]['toThrow'](), _0x213aa5 = function () {
                return !![];
            }, _0x4fa558;
        _0x4fa558 = _0x37307e[_0x3251b9(0x1aa)](_0x213aa5), expect(_0x4fa558['pass'])[_0x3251b9(0x1ab)](![]), expect(_0x4fa558['message'])['toEqual'](_0x3251b9(0x1c0));
    }), it(_0x189be4(0x1c2), function () {
        var _0x178cfc = _0x189be4, _0x491d8d = {
                'equals': jasmine[_0x178cfc(0x1a6)]('delegated-equal')['and'][_0x178cfc(0x1bf)](!![]),
                'pp': jasmineUnderTest[_0x178cfc(0x1bd)]()
            }, _0x4080a7 = jasmineUnderTest[_0x178cfc(0x1a8)][_0x178cfc(0x1b4)](_0x491d8d), _0x5f49e5 = function () {
                throw 0x5;
            }, _0x5e04eb;
        _0x5e04eb = _0x4080a7[_0x178cfc(0x1aa)](_0x5f49e5), expect(_0x5e04eb[_0x178cfc(0x1a2)])[_0x178cfc(0x1ab)](!![]), expect(_0x5e04eb[_0x178cfc(0x1a5)]())[_0x178cfc(0x1b1)]('Expected\x20function\x20not\x20to\x20throw,\x20but\x20it\x20threw\x205.');
    }), it('passes\x20even\x20if\x20what\x20is\x20thrown\x20is\x20falsy', function () {
        var _0x30f82e = _0x189be4, _0x47b58c = jasmineUnderTest['matchers'][_0x30f82e(0x1b4)]({ 'pp': jasmineUnderTest['makePrettyPrinter']() }), _0x382ec6 = function () {
                throw undefined;
            }, _0x48744f;
        _0x48744f = _0x47b58c[_0x30f82e(0x1aa)](_0x382ec6), expect(_0x48744f[_0x30f82e(0x1a2)])[_0x30f82e(0x1ab)](!![]), expect(_0x48744f['message']())[_0x30f82e(0x1b1)](_0x30f82e(0x1b6));
    }), it(_0x189be4(0x1a9), function () {
        var _0x8a4cc4 = _0x189be4, _0x3eec07 = {
                'equals': jasmine['createSpy'](_0x8a4cc4(0x1be))[_0x8a4cc4(0x1b0)]['returnValue'](!![]),
                'pp': jasmineUnderTest[_0x8a4cc4(0x1bd)]()
            }, _0x438339 = jasmineUnderTest[_0x8a4cc4(0x1a8)][_0x8a4cc4(0x1b4)](_0x3eec07), _0x159f2f = function () {
                throw 0x5;
            }, _0x1fc3fd;
        _0x1fc3fd = _0x438339[_0x8a4cc4(0x1aa)](_0x159f2f, 0x5), expect(_0x1fc3fd[_0x8a4cc4(0x1a2)])[_0x8a4cc4(0x1ab)](!![]), expect(_0x1fc3fd[_0x8a4cc4(0x1a5)]())[_0x8a4cc4(0x1b1)]('Expected\x20function\x20not\x20to\x20throw\x205.');
    }), it(_0x189be4(0x1b2), function () {
        var _0x280b08 = _0x189be4, _0x4093f4 = {
                'equals': jasmine[_0x280b08(0x1a6)](_0x280b08(0x1be))['and'][_0x280b08(0x1bf)](![]),
                'pp': jasmineUnderTest[_0x280b08(0x1bd)]()
            }, _0x518764 = jasmineUnderTest[_0x280b08(0x1a8)][_0x280b08(0x1b4)](_0x4093f4), _0x5ce4de = function () {
                throw 0x5;
            }, _0x1f81d3;
        _0x1f81d3 = _0x518764[_0x280b08(0x1aa)](_0x5ce4de, _0x280b08(0x1bb)), expect(_0x1f81d3['pass'])[_0x280b08(0x1ab)](![]), expect(_0x1f81d3[_0x280b08(0x1a5)]())['toEqual'](_0x280b08(0x1a1));
    }), it('fails\x20if\x20what\x20is\x20thrown\x20is\x20not\x20equivalent\x20to\x20undefined', function () {
        var _0x4573c6 = _0x189be4, _0x52c16a = {
                'equals': jasmine[_0x4573c6(0x1a6)](_0x4573c6(0x1be))['and'][_0x4573c6(0x1bf)](![]),
                'pp': jasmineUnderTest[_0x4573c6(0x1bd)]()
            }, _0x280cde = jasmineUnderTest[_0x4573c6(0x1a8)][_0x4573c6(0x1b4)](_0x52c16a), _0xbfa72c = function () {
                throw 0x5;
            }, _0x3c880e;
        _0x3c880e = _0x280cde[_0x4573c6(0x1aa)](_0xbfa72c, void 0x0), expect(_0x3c880e[_0x4573c6(0x1a2)])[_0x4573c6(0x1ab)](![]), expect(_0x3c880e[_0x4573c6(0x1a5)]())[_0x4573c6(0x1b1)](_0x4573c6(0x1b3));
    });
}));