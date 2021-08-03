var a80_0x34af = [
    '2089zCLyvh',
    '233530jWNhKB',
    'Expected\x20a\x20promise\x20to\x20be\x20rejected\x20with\x20TypeError:\x20\x27foo\x27\x20but\x20it\x20was\x20rejected\x20with\x20type\x20Error.',
    '461PEplTW',
    'asyncMatchers',
    '21389AXugVU',
    'Expected\x20a\x20promise\x20not\x20to\x20be\x20rejected\x20with\x20Error:\x20\x27foo\x27,\x20but\x20it\x20was.',
    '314819yaesGR',
    'Expected\x20a\x20promise\x20to\x20be\x20rejected\x20with\x20Error:\x20\x27foo\x27\x20but\x20it\x20was\x20rejected\x20with\x20\x27foo\x27.',
    'foo',
    'Expected\x20a\x20promise\x20to\x20be\x20rejected\x20with\x20Error:\x20\x27bar\x27\x20but\x20it\x20was\x20rejected\x20with\x20Error:\x20foo.',
    'requirePromises',
    'MatchersUtil',
    'fails\x20when\x20rejected\x20with\x20non\x20Error\x20type',
    'bar',
    'getEnv',
    'reject',
    'makePrettyPrinter',
    'Expected\x20a\x20promise\x20not\x20to\x20be\x20rejected\x20with\x20Error:\x20/foo/,\x20but\x20it\x20was.',
    'objectContaining',
    'then',
    'fails\x20when\x20Error\x20message\x20mismatches',
    'passes\x20when\x20Error\x20message\x20matches\x20a\x20RegExp',
    'passes\x20when\x20Error\x20matches\x20and\x20is\x20exactly\x20Error',
    'passes\x20when\x20no\x20arguments',
    'fails\x20if\x20actual\x20is\x20not\x20a\x20promise',
    'Expected\x20a\x20promise\x20not\x20to\x20be\x20rejected\x20with\x20TypeError:\x20\x27foo\x27,\x20but\x20it\x20was.',
    '635994ZInONT',
    'toThrowError',
    'compare',
    'passes\x20when\x20Error\x20message\x20is\x20empty',
    'Expected\x20a\x20promise\x20not\x20to\x20be\x20rejected\x20with\x20TypeError,\x20but\x20it\x20was.',
    '575743WMWIoM',
    '1067384bOukEI',
    'toEqual',
    'Expected\x20a\x20promise\x20to\x20be\x20rejected\x20but\x20it\x20was\x20resolved.',
    '31SBijRy',
    'Expected\x20a\x20promise\x20not\x20to\x20be\x20rejected\x20with\x20Error,\x20but\x20it\x20was.',
    'toBeRejectedWithError'
];
function a80_0x4905(_0x1cbec9, _0x526fa1) {
    return a80_0x4905 = function (_0x34afe6, _0x4905f7) {
        _0x34afe6 = _0x34afe6 - 0x90;
        var _0x379d2b = a80_0x34af[_0x34afe6];
        return _0x379d2b;
    }, a80_0x4905(_0x1cbec9, _0x526fa1);
}
(function (_0x58fceb, _0x36e91d) {
    var _0x1c5aef = a80_0x4905;
    while (!![]) {
        try {
            var _0x4186b8 = parseInt(_0x1c5aef(0xa3)) + parseInt(_0x1c5aef(0x96)) + -parseInt(_0x1c5aef(0x9b)) + -parseInt(_0x1c5aef(0xa5)) * -parseInt(_0x1c5aef(0xa2)) + -parseInt(_0x1c5aef(0x9c)) + -parseInt(_0x1c5aef(0xa9)) + parseInt(_0x1c5aef(0xa7)) * parseInt(_0x1c5aef(0x9f));
            if (_0x4186b8 === _0x36e91d)
                break;
            else
                _0x58fceb['push'](_0x58fceb['shift']());
        } catch (_0xbe759c) {
            _0x58fceb['push'](_0x58fceb['shift']());
        }
    }
}(a80_0x34af, 0x83442), describe('#toBeRejectedWithError', function () {
    var _0x19a369 = a80_0x4905;
    it('passes\x20when\x20Error\x20type\x20matches', function () {
        var _0x37ceb2 = a80_0x4905;
        jasmine[_0x37ceb2(0xb1)]()[_0x37ceb2(0xad)]();
        var _0x10a905 = new jasmineUnderTest[(_0x37ceb2(0xae))]({ 'pp': jasmineUnderTest[_0x37ceb2(0xb3)]() }), _0x492328 = jasmineUnderTest[_0x37ceb2(0xa6)][_0x37ceb2(0xa1)](_0x10a905), _0x59837a = Promise[_0x37ceb2(0xb2)](new TypeError(_0x37ceb2(0xab)));
        return _0x492328[_0x37ceb2(0x98)](_0x59837a, TypeError)[_0x37ceb2(0xb6)](function (_0x14b91a) {
            var _0x2efbde = _0x37ceb2;
            expect(_0x14b91a)['toEqual'](jasmine['objectContaining']({
                'pass': !![],
                'message': _0x2efbde(0x9a)
            }));
        });
    }), it('passes\x20when\x20Error\x20type\x20and\x20message\x20matches', function () {
        var _0x1e62f4 = a80_0x4905;
        jasmine[_0x1e62f4(0xb1)]()[_0x1e62f4(0xad)]();
        var _0x8b4939 = new jasmineUnderTest[(_0x1e62f4(0xae))]({ 'pp': jasmineUnderTest['makePrettyPrinter']() }), _0x14dfe6 = jasmineUnderTest[_0x1e62f4(0xa6)][_0x1e62f4(0xa1)](_0x8b4939), _0xb2adc6 = Promise['reject'](new TypeError(_0x1e62f4(0xab)));
        return _0x14dfe6[_0x1e62f4(0x98)](_0xb2adc6, TypeError, 'foo')[_0x1e62f4(0xb6)](function (_0x5df337) {
            var _0x4c1583 = _0x1e62f4;
            expect(_0x5df337)['toEqual'](jasmine[_0x4c1583(0xb5)]({
                'pass': !![],
                'message': _0x4c1583(0x95)
            }));
        });
    }), it(_0x19a369(0x92), function () {
        var _0x176d63 = _0x19a369;
        jasmine[_0x176d63(0xb1)]()[_0x176d63(0xad)]();
        var _0x49d554 = new jasmineUnderTest[(_0x176d63(0xae))]({ 'pp': jasmineUnderTest['makePrettyPrinter']() }), _0x5db5ba = jasmineUnderTest[_0x176d63(0xa6)][_0x176d63(0xa1)](_0x49d554), _0x22b1cc = Promise[_0x176d63(0xb2)](new Error());
        return _0x5db5ba[_0x176d63(0x98)](_0x22b1cc, Error)['then'](function (_0x34e9c3) {
            var _0x6807a1 = _0x176d63;
            expect(_0x34e9c3)[_0x6807a1(0x9d)](jasmine[_0x6807a1(0xb5)]({
                'pass': !![],
                'message': _0x6807a1(0xa0)
            }));
        });
    }), it('passes\x20when\x20Error\x20message\x20matches\x20a\x20string', function () {
        var _0x5ce251 = _0x19a369;
        jasmine[_0x5ce251(0xb1)]()['requirePromises']();
        var _0xdc698e = new jasmineUnderTest[(_0x5ce251(0xae))]({ 'pp': jasmineUnderTest[_0x5ce251(0xb3)]() }), _0x5dca29 = jasmineUnderTest[_0x5ce251(0xa6)]['toBeRejectedWithError'](_0xdc698e), _0x494d80 = Promise[_0x5ce251(0xb2)](new Error('foo'));
        return _0x5dca29[_0x5ce251(0x98)](_0x494d80, _0x5ce251(0xab))[_0x5ce251(0xb6)](function (_0x2bf6bd) {
            var _0x587d25 = _0x5ce251;
            expect(_0x2bf6bd)[_0x587d25(0x9d)](jasmine[_0x587d25(0xb5)]({
                'pass': !![],
                'message': _0x587d25(0xa8)
            }));
        });
    }), it(_0x19a369(0x91), function () {
        var _0x33ac84 = _0x19a369;
        jasmine['getEnv']()['requirePromises']();
        var _0x1aafad = new jasmineUnderTest[(_0x33ac84(0xae))]({ 'pp': jasmineUnderTest['makePrettyPrinter']() }), _0x34ca38 = jasmineUnderTest[_0x33ac84(0xa6)][_0x33ac84(0xa1)](_0x1aafad), _0x7c92ae = Promise[_0x33ac84(0xb2)](new Error(_0x33ac84(0xab)));
        return _0x34ca38[_0x33ac84(0x98)](_0x7c92ae, /foo/)[_0x33ac84(0xb6)](function (_0x9426af) {
            var _0x2809dc = _0x33ac84;
            expect(_0x9426af)['toEqual'](jasmine[_0x2809dc(0xb5)]({
                'pass': !![],
                'message': _0x2809dc(0xb4)
            }));
        });
    }), it(_0x19a369(0x99), function () {
        var _0x26cb23 = _0x19a369;
        jasmine[_0x26cb23(0xb1)]()[_0x26cb23(0xad)]();
        var _0x1becaa = new jasmineUnderTest[(_0x26cb23(0xae))]({ 'pp': jasmineUnderTest[_0x26cb23(0xb3)]() }), _0x4a6e43 = jasmineUnderTest[_0x26cb23(0xa6)]['toBeRejectedWithError'](_0x1becaa), _0x576d5a = Promise[_0x26cb23(0xb2)](new Error());
        return _0x4a6e43[_0x26cb23(0x98)](_0x576d5a, '')[_0x26cb23(0xb6)](function (_0x62d8da) {
            var _0x2d08a2 = _0x26cb23;
            expect(_0x62d8da)[_0x2d08a2(0x9d)](jasmine['objectContaining']({
                'pass': !![],
                'message': 'Expected\x20a\x20promise\x20not\x20to\x20be\x20rejected\x20with\x20Error:\x20\x27\x27,\x20but\x20it\x20was.'
            }));
        });
    }), it(_0x19a369(0x93), function () {
        var _0x208023 = _0x19a369;
        jasmine[_0x208023(0xb1)]()[_0x208023(0xad)]();
        var _0x1bf730 = new jasmineUnderTest[(_0x208023(0xae))]({ 'pp': jasmineUnderTest[_0x208023(0xb3)]() }), _0x3484e1 = jasmineUnderTest[_0x208023(0xa6)]['toBeRejectedWithError'](_0x1bf730), _0x21bc02 = Promise[_0x208023(0xb2)](new Error());
        return _0x3484e1[_0x208023(0x98)](_0x21bc02, void 0x0)[_0x208023(0xb6)](function (_0x59116e) {
            var _0x42ad12 = _0x208023;
            expect(_0x59116e)[_0x42ad12(0x9d)](jasmine['objectContaining']({
                'pass': !![],
                'message': _0x42ad12(0xa0)
            }));
        });
    }), it('fails\x20when\x20resolved', function () {
        var _0x176c53 = _0x19a369;
        jasmine['getEnv']()[_0x176c53(0xad)]();
        var _0x325b8f = new jasmineUnderTest[(_0x176c53(0xae))]({ 'pp': jasmineUnderTest['makePrettyPrinter']() }), _0x32727d = jasmineUnderTest['asyncMatchers']['toBeRejectedWithError'](_0x325b8f), _0x397e73 = Promise['resolve'](new Error(_0x176c53(0xab)));
        return _0x32727d['compare'](_0x397e73, _0x176c53(0xab))[_0x176c53(0xb6)](function (_0x38c181) {
            var _0x5928c2 = _0x176c53;
            expect(_0x38c181)[_0x5928c2(0x9d)](jasmine[_0x5928c2(0xb5)]({
                'pass': ![],
                'message': _0x5928c2(0x9e)
            }));
        });
    }), it(_0x19a369(0xaf), function () {
        var _0x20eaaa = _0x19a369;
        jasmine[_0x20eaaa(0xb1)]()['requirePromises']();
        var _0x199da6 = new jasmineUnderTest[(_0x20eaaa(0xae))]({ 'pp': jasmineUnderTest['makePrettyPrinter']() }), _0x1eff40 = jasmineUnderTest[_0x20eaaa(0xa6)]['toBeRejectedWithError'](_0x199da6), _0x5ad9f9 = Promise['reject']('foo');
        return _0x1eff40['compare'](_0x5ad9f9, 'foo')['then'](function (_0x4502aa) {
            var _0xd9fd27 = _0x20eaaa;
            expect(_0x4502aa)[_0xd9fd27(0x9d)](jasmine[_0xd9fd27(0xb5)]({
                'pass': ![],
                'message': _0xd9fd27(0xaa)
            }));
        });
    }), it('fails\x20when\x20Error\x20type\x20mismatches', function () {
        var _0x201a03 = _0x19a369;
        jasmine[_0x201a03(0xb1)]()[_0x201a03(0xad)]();
        var _0x14669a = new jasmineUnderTest[(_0x201a03(0xae))]({ 'pp': jasmineUnderTest[_0x201a03(0xb3)]() }), _0x54d882 = jasmineUnderTest[_0x201a03(0xa6)][_0x201a03(0xa1)](_0x14669a), _0x40666d = Promise['reject'](new Error(_0x201a03(0xab)));
        return _0x54d882['compare'](_0x40666d, TypeError, _0x201a03(0xab))[_0x201a03(0xb6)](function (_0x54b1a9) {
            var _0x2cb15f = _0x201a03;
            expect(_0x54b1a9)['toEqual'](jasmine[_0x2cb15f(0xb5)]({
                'pass': ![],
                'message': _0x2cb15f(0xa4)
            }));
        });
    }), it(_0x19a369(0x90), function () {
        var _0x2de99d = _0x19a369;
        jasmine[_0x2de99d(0xb1)]()[_0x2de99d(0xad)]();
        var _0x5ecc42 = new jasmineUnderTest['MatchersUtil']({ 'pp': jasmineUnderTest[_0x2de99d(0xb3)]() }), _0x3a0b68 = jasmineUnderTest[_0x2de99d(0xa6)][_0x2de99d(0xa1)](_0x5ecc42), _0x1116e = Promise[_0x2de99d(0xb2)](new Error(_0x2de99d(0xab)));
        return _0x3a0b68[_0x2de99d(0x98)](_0x1116e, _0x2de99d(0xb0))[_0x2de99d(0xb6)](function (_0xb0a1e3) {
            var _0x14f92e = _0x2de99d;
            expect(_0xb0a1e3)['toEqual'](jasmine[_0x14f92e(0xb5)]({
                'pass': ![],
                'message': _0x14f92e(0xac)
            }));
        });
    }), it(_0x19a369(0x94), function () {
        var _0x51f34a = _0x19a369, _0x1fd846 = new jasmineUnderTest[(_0x51f34a(0xae))]({ 'pp': jasmineUnderTest[_0x51f34a(0xb3)]() }), _0x4fc81a = jasmineUnderTest[_0x51f34a(0xa6)]['toBeRejectedWithError'](_0x1fd846), _0x2a91b8 = 'not\x20a\x20promise';
        function _0x1d238b() {
            var _0x56afe5 = _0x51f34a;
            return _0x4fc81a[_0x56afe5(0x98)](_0x2a91b8);
        }
        expect(_0x1d238b)[_0x51f34a(0x97)]('Expected\x20toBeRejectedWithError\x20to\x20be\x20called\x20on\x20a\x20promise.');
    });
}));