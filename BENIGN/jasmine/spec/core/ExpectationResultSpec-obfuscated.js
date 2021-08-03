var a32_0x2a88 = [
    'and',
    'assert\x20==',
    'code',
    'defaults\x20to\x20passed',
    'handles\x20nodejs\x20assertions',
    '25uqLiWy',
    'assert',
    'toEqual',
    'toBe',
    '846441VXJfBA',
    'stack',
    'delegates\x20stack\x20formatting\x20to\x20the\x20provided\x20formatter\x20if\x20there\x20was\x20a\x20provided\x20errorForStack',
    'message\x20defaults\x20to\x20Passed\x20for\x20passing\x20specs',
    'stack\x20formatter',
    'ERR_ASSERTION',
    'message\x20returns\x20the\x20message\x20for\x20failing\x20expectations',
    'some-value',
    'Passed.',
    '540670PBKHJk',
    'exception\x20message\x20formatter',
    '224859ujqKxJ',
    '34399rdWnjw',
    'actual',
    'returnValue',
    'foo',
    '421106HWSkbZ',
    'undefined',
    'matcherName',
    'message',
    'delegates\x20message\x20formatting\x20to\x20the\x20provided\x20formatter\x20if\x20there\x20was\x20an\x20Error',
    'delegates\x20stack\x20formatting\x20to\x20the\x20provided\x20formatter\x20if\x20there\x20was\x20an\x20Error',
    '821827kSqHKZ',
    'actual\x20returns\x20passed\x20actual',
    'expected\x20returns\x20passed\x20expected',
    'toHaveBeenCalledWith',
    '850300yzDjOv',
    'expected',
    'buildExpectationResult',
    'createSpy'
];
function a32_0x1dd9(_0x3df6aa, _0x50bedf) {
    return a32_0x1dd9 = function (_0x2a886b, _0x1dd985) {
        _0x2a886b = _0x2a886b - 0x1aa;
        var _0x40ea0e = a32_0x2a88[_0x2a886b];
        return _0x40ea0e;
    }, a32_0x1dd9(_0x3df6aa, _0x50bedf);
}
(function (_0x2efac4, _0x5e47bb) {
    var _0x4bbbc0 = a32_0x1dd9;
    while (!![]) {
        try {
            var _0x5097ed = -parseInt(_0x4bbbc0(0x1ce)) + -parseInt(_0x4bbbc0(0x1ac)) + -parseInt(_0x4bbbc0(0x1b6)) + parseInt(_0x4bbbc0(0x1cf)) * parseInt(_0x4bbbc0(0x1bf)) + parseInt(_0x4bbbc0(0x1c3)) + parseInt(_0x4bbbc0(0x1b2)) + -parseInt(_0x4bbbc0(0x1cc));
            if (_0x5097ed === _0x5e47bb)
                break;
            else
                _0x2efac4['push'](_0x2efac4['shift']());
        } catch (_0x2ab72f) {
            _0x2efac4['push'](_0x2efac4['shift']());
        }
    }
}(a32_0x2a88, 0x77f2c), describe('buildExpectationResult', function () {
    var _0x1ddc4b = a32_0x1dd9;
    it(_0x1ddc4b(0x1bd), function () {
        var _0x28c81 = _0x1ddc4b, _0x458276 = jasmineUnderTest[_0x28c81(0x1b8)]({ 'passed': 'some-value' });
        expect(_0x458276['passed'])[_0x28c81(0x1c2)](_0x28c81(0x1ca));
    }), it(_0x1ddc4b(0x1c6), function () {
        var _0x390108 = _0x1ddc4b, _0x2b451f = jasmineUnderTest['buildExpectationResult']({
                'passed': !![],
                'message': _0x390108(0x1ca)
            });
        expect(_0x2b451f[_0x390108(0x1af)])[_0x390108(0x1c2)](_0x390108(0x1cb));
    }), it(_0x1ddc4b(0x1c9), function () {
        var _0x570cb7 = _0x1ddc4b, _0x410cee = jasmineUnderTest[_0x570cb7(0x1b8)]({
                'passed': ![],
                'message': 'some-value'
            });
        expect(_0x410cee[_0x570cb7(0x1af)])['toBe'](_0x570cb7(0x1ca));
    }), it(_0x1ddc4b(0x1b0), function () {
        var _0x50d95f = _0x1ddc4b, _0x464c9d = { 'message': 'foo' }, _0x1e58f6 = jasmine[_0x50d95f(0x1b9)](_0x50d95f(0x1cd))[_0x50d95f(0x1ba)][_0x50d95f(0x1aa)](_0x464c9d['message']), _0x1a17ef = jasmineUnderTest['buildExpectationResult']({
                'passed': ![],
                'error': _0x464c9d,
                'messageFormatter': _0x1e58f6
            });
        expect(_0x1e58f6)[_0x50d95f(0x1b5)](_0x464c9d), expect(_0x1a17ef[_0x50d95f(0x1af)])[_0x50d95f(0x1c1)]('foo');
    }), it(_0x1ddc4b(0x1b1), function () {
        var _0x3bbf10 = _0x1ddc4b, _0x1ba722 = { 'stack': 'foo' }, _0x3ad5f4 = jasmine[_0x3bbf10(0x1b9)](_0x3bbf10(0x1c7))['and'][_0x3bbf10(0x1aa)](_0x1ba722['stack']), _0x475ace = jasmineUnderTest[_0x3bbf10(0x1b8)]({
                'passed': ![],
                'error': _0x1ba722,
                'stackFormatter': _0x3ad5f4
            });
        expect(_0x3ad5f4)[_0x3bbf10(0x1b5)](_0x1ba722), expect(_0x475ace[_0x3bbf10(0x1c4)])[_0x3bbf10(0x1c1)](_0x3bbf10(0x1ab));
    }), it(_0x1ddc4b(0x1c5), function () {
        var _0x479ad0 = _0x1ddc4b, _0xd9a500 = { 'stack': _0x479ad0(0x1ab) }, _0x1033ac = jasmine[_0x479ad0(0x1b9)]('stack\x20formatter')[_0x479ad0(0x1ba)]['returnValue'](_0xd9a500[_0x479ad0(0x1c4)]), _0x307efd = jasmineUnderTest[_0x479ad0(0x1b8)]({
                'passed': ![],
                'errorForStack': _0xd9a500,
                'stackFormatter': _0x1033ac
            });
        expect(_0x1033ac)['toHaveBeenCalledWith'](_0xd9a500), expect(_0x307efd[_0x479ad0(0x1c4)])[_0x479ad0(0x1c1)]('foo');
    }), it('matcherName\x20returns\x20passed\x20matcherName', function () {
        var _0x5acbad = _0x1ddc4b, _0x3c76c8 = jasmineUnderTest[_0x5acbad(0x1b8)]({ 'matcherName': _0x5acbad(0x1ca) });
        expect(_0x3c76c8[_0x5acbad(0x1ae)])['toBe'](_0x5acbad(0x1ca));
    }), it(_0x1ddc4b(0x1b4), function () {
        var _0x1eb2ce = _0x1ddc4b, _0x1ab723 = jasmineUnderTest[_0x1eb2ce(0x1b8)]({ 'expected': _0x1eb2ce(0x1ca) });
        expect(_0x1ab723[_0x1eb2ce(0x1b7)])[_0x1eb2ce(0x1c2)](_0x1eb2ce(0x1ca));
    }), it(_0x1ddc4b(0x1b3), function () {
        var _0x83611d = _0x1ddc4b, _0x5d1868 = jasmineUnderTest[_0x83611d(0x1b8)]({ 'actual': _0x83611d(0x1ca) });
        expect(_0x5d1868[_0x83611d(0x1d0)])[_0x83611d(0x1c2)](_0x83611d(0x1ca));
    }), it(_0x1ddc4b(0x1be), function () {
        var _0x1184e4 = _0x1ddc4b;
        if (typeof require === _0x1184e4(0x1ad))
            return;
        var _0x437bef = require(_0x1184e4(0x1c0)), _0x1c5e6b, _0x54ae0d = 0x20e5, _0x36b29b = 'JasmineExpectationTestValue';
        try {
            _0x437bef['equal'](_0x54ae0d, _0x36b29b);
        } catch (_0x546e1a) {
            _0x1c5e6b = _0x546e1a;
        }
        expect(_0x1c5e6b[_0x1184e4(0x1bc)])[_0x1184e4(0x1c1)](_0x1184e4(0x1c8)), expect(_0x1c5e6b['actual'])[_0x1184e4(0x1c1)](_0x54ae0d), expect(_0x1c5e6b[_0x1184e4(0x1b7)])[_0x1184e4(0x1c1)](_0x36b29b), expect(_0x1c5e6b['operator'])[_0x1184e4(0x1c1)]('==');
        var _0x372d1b = jasmineUnderTest[_0x1184e4(0x1b8)]({
            'passed': ![],
            'matcherName': '',
            'expected': '',
            'actual': '',
            'error': _0x1c5e6b
        });
        expect(_0x372d1b[_0x1184e4(0x1bc)])[_0x1184e4(0x1c1)](_0x1184e4(0x1c8)), expect(_0x372d1b[_0x1184e4(0x1d0)])[_0x1184e4(0x1c1)](_0x54ae0d), expect(_0x372d1b[_0x1184e4(0x1b7)])['toEqual'](_0x36b29b), expect(_0x372d1b['matcherName'])[_0x1184e4(0x1c1)](_0x1184e4(0x1bb));
    });
}));