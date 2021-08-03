var a83_0x4419 = [
    'fails\x20if\x20actual\x20is\x20not\x20a\x20promise',
    'Expected\x20a\x20promise\x20to\x20be\x20resolved\x20to\x20\x27\x27\x20but\x20it\x20was\x20rejected\x20',
    'passes\x20if\x20the\x20promise\x20is\x20resolved\x20to\x20the\x20expected\x20value',
    '337IoVDJY',
    '135095jdGBfj',
    'reject',
    'makePrettyPrinter',
    'Expected\x20a\x20promise\x20not\x20to\x20be\x20resolved\x20to\x20true.',
    '13241BhhHMR',
    'supports\x20custom\x20equality\x20testers',
    'getEnv',
    'with\x20Error:\x20AsyncExpectationSpec\x20error.',
    'toEqual',
    '5IJchWQ',
    'builds\x20its\x20message\x20correctly\x20when\x20negated',
    '55619GAhGxg',
    'Expected\x20a\x20promise\x20to\x20be\x20resolved\x20to\x20Object({\x20foo:\x2042\x20})\x20but\x20it\x20was\x20resolved\x20to\x20Object({\x20foo:\x2017\x20}).',
    '48056vQBVHg',
    'compare',
    'Expected\x20toBeResolvedTo\x20to\x20be\x20called\x20on\x20a\x20promise.',
    'toThrowError',
    '#toBeResolvedTo',
    'resolve',
    'MatchersUtil',
    'expected',
    'fails\x20if\x20the\x20promise\x20is\x20rejected',
    '155304ZRKmmw',
    '13TNyAiG',
    '20308NvNWYN',
    'fails\x20if\x20the\x20promise\x20is\x20resolved\x20to\x20a\x20different\x20value',
    '23HcDnMG',
    'asyncMatchers',
    'toBeResolvedTo',
    'requirePromises',
    'then',
    'actual',
    'objectContaining'
];
function a83_0x4f74(_0x2b6f1f, _0x1f177c) {
    return a83_0x4f74 = function (_0x4419d5, _0x4f740b) {
        _0x4419d5 = _0x4419d5 - 0x18f;
        var _0x1e4f8f = a83_0x4419[_0x4419d5];
        return _0x1e4f8f;
    }, a83_0x4f74(_0x2b6f1f, _0x1f177c);
}
var a83_0x46beb3 = a83_0x4f74;
(function (_0x48b0a9, _0x48168d) {
    var _0x50363b = a83_0x4f74;
    while (!![]) {
        try {
            var _0x35ce30 = parseInt(_0x50363b(0x195)) + -parseInt(_0x50363b(0x1a0)) + -parseInt(_0x50363b(0x19e)) + parseInt(_0x50363b(0x1b1)) * -parseInt(_0x50363b(0x19f)) + parseInt(_0x50363b(0x1ad)) + parseInt(_0x50363b(0x1a2)) * -parseInt(_0x50363b(0x1ac)) + parseInt(_0x50363b(0x191)) * parseInt(_0x50363b(0x193));
            if (_0x35ce30 === _0x48168d)
                break;
            else
                _0x48b0a9['push'](_0x48b0a9['shift']());
        } catch (_0x55eabf) {
            _0x48b0a9['push'](_0x48b0a9['shift']());
        }
    }
}(a83_0x4419, 0x19d16), describe(a83_0x46beb3(0x199), function () {
    var _0x1258ea = a83_0x46beb3;
    it(_0x1258ea(0x1ab), function () {
        var _0x29d76a = _0x1258ea;
        jasmine['getEnv']()[_0x29d76a(0x1a5)]();
        var _0x949933 = new jasmineUnderTest['MatchersUtil'](), _0xac0fdd = jasmineUnderTest['asyncMatchers']['toBeResolvedTo'](_0x949933), _0x6b7cf6 = Promise['resolve']({ 'foo': 0x2a });
        return _0xac0fdd[_0x29d76a(0x196)](_0x6b7cf6, { 'foo': 0x2a })[_0x29d76a(0x1a6)](function (_0x5d882c) {
            var _0x536a50 = _0x29d76a;
            expect(_0x5d882c)[_0x536a50(0x190)](jasmine['objectContaining']({ 'pass': !![] }));
        });
    }), it(_0x1258ea(0x19d), function () {
        var _0x312da7 = _0x1258ea;
        jasmine['getEnv']()[_0x312da7(0x1a5)]();
        var _0x53149d = new jasmineUnderTest['MatchersUtil']({ 'pp': jasmineUnderTest[_0x312da7(0x1af)]() }), _0x5ae2f7 = jasmineUnderTest['asyncMatchers'][_0x312da7(0x1a4)](_0x53149d), _0x1f8710 = Promise[_0x312da7(0x1ae)](new Error('AsyncExpectationSpec\x20error'));
        return _0x5ae2f7['compare'](_0x1f8710, '')['then'](function (_0x2161ff) {
            var _0x2cf992 = _0x312da7;
            expect(_0x2161ff)[_0x2cf992(0x190)](jasmine[_0x2cf992(0x1a8)]({
                'pass': ![],
                'message': _0x2cf992(0x1aa) + _0x2cf992(0x18f)
            }));
        });
    }), it(_0x1258ea(0x1a1), function () {
        var _0x32e9c1 = _0x1258ea;
        jasmine[_0x32e9c1(0x1b3)]()['requirePromises']();
        var _0x3384c4 = new jasmineUnderTest[(_0x32e9c1(0x19b))]({ 'pp': jasmineUnderTest[_0x32e9c1(0x1af)]() }), _0x34b1d6 = jasmineUnderTest[_0x32e9c1(0x1a3)][_0x32e9c1(0x1a4)](_0x3384c4), _0x50eaca = Promise[_0x32e9c1(0x19a)]({ 'foo': 0x11 });
        return _0x34b1d6['compare'](_0x50eaca, { 'foo': 0x2a })[_0x32e9c1(0x1a6)](function (_0x18d9e9) {
            var _0x10bd2e = _0x32e9c1;
            expect(_0x18d9e9)[_0x10bd2e(0x190)](jasmine[_0x10bd2e(0x1a8)]({
                'pass': ![],
                'message': _0x10bd2e(0x194)
            }));
        });
    }), it(_0x1258ea(0x192), function () {
        var _0x4e3277 = _0x1258ea;
        jasmine[_0x4e3277(0x1b3)]()['requirePromises']();
        var _0x442d62 = new jasmineUnderTest[(_0x4e3277(0x19b))]({ 'pp': jasmineUnderTest[_0x4e3277(0x1af)]() }), _0x283179 = jasmineUnderTest[_0x4e3277(0x1a3)][_0x4e3277(0x1a4)](_0x442d62), _0x44363c = Promise[_0x4e3277(0x19a)](!![]);
        return _0x283179[_0x4e3277(0x196)](_0x44363c, !![])[_0x4e3277(0x1a6)](function (_0x105b77) {
            var _0x4b9491 = _0x4e3277;
            expect(_0x105b77)[_0x4b9491(0x190)](jasmine['objectContaining']({
                'pass': !![],
                'message': _0x4b9491(0x1b0)
            }));
        });
    }), it(_0x1258ea(0x1b2), function () {
        var _0x351ef3 = _0x1258ea;
        jasmine[_0x351ef3(0x1b3)]()[_0x351ef3(0x1a5)]();
        var _0x14c5d = [function () {
                    return !![];
                }], _0x84395e = new jasmineUnderTest[(_0x351ef3(0x19b))]({
                'customTesters': _0x14c5d,
                'pp': jasmineUnderTest['makePrettyPrinter']()
            }), _0x1a96b5 = jasmineUnderTest['asyncMatchers'][_0x351ef3(0x1a4)](_0x84395e), _0x9bbe8e = Promise[_0x351ef3(0x19a)](_0x351ef3(0x1a7));
        return _0x1a96b5['compare'](_0x9bbe8e, _0x351ef3(0x19c))[_0x351ef3(0x1a6)](function (_0x25cebd) {
            var _0x6100b6 = _0x351ef3;
            expect(_0x25cebd)['toEqual'](jasmine[_0x6100b6(0x1a8)]({ 'pass': !![] }));
        });
    }), it(_0x1258ea(0x1a9), function () {
        var _0x3349e5 = _0x1258ea, _0x5b576c = new jasmineUnderTest['MatchersUtil']({ 'pp': jasmineUnderTest[_0x3349e5(0x1af)]() }), _0x2de7a6 = jasmineUnderTest['asyncMatchers']['toBeResolvedTo'](_0x5b576c), _0x35e169 = 'not\x20a\x20promise';
        function _0x39c23c() {
            return _0x2de7a6['compare'](_0x35e169);
        }
        expect(_0x39c23c)[_0x3349e5(0x198)](_0x3349e5(0x197));
    });
}));