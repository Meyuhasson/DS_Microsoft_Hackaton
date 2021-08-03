var a24_0x3ae6 = [
    'thisFor',
    'foo',
    '840284VauznE',
    'returns\x20any\x20empty\x20array\x20when\x20there\x20was\x20no\x20call',
    'not',
    'saveArgumentsByValue',
    'saves\x20primitive\x20arguments\x20by\x20value',
    'returns\x20a\x20useful\x20falsy\x20value\x20when\x20there\x20isn\x27t\x20a\x20last\x20(most\x20recent)\x20call',
    'allows\x20the\x20tracking\x20to\x20be\x20reset',
    'any',
    'argsFor',
    'all',
    '3POLbgu',
    'tracks\x20the\x20params\x20from\x20each\x20execution',
    'returns\x20a\x20useful\x20falsy\x20value\x20when\x20there\x20isn\x27t\x20a\x20first\x20(oldest)\x20call',
    'mostRecent',
    '95287abAyux',
    '219008OoxrTa',
    '355117CkYIBC',
    '5716zPnJAq',
    'track',
    'count',
    'toBeFalsy',
    '3sWlQPk',
    'toBe',
    'bar',
    'allows\x20object\x20arguments\x20to\x20be\x20shallow\x20cloned',
    'toEqual',
    'CallTracker',
    'simplifies\x20access\x20to\x20the\x20arguments\x20for\x20the\x20first\x20(oldest)\x20call',
    'tracks\x20the\x20\x27this\x27\x20object\x20from\x20each\x20execution',
    'args',
    'allows\x20access\x20for\x20the\x20arguments\x20for\x20all\x20calls',
    '1127570dATcDM',
    'tracks\x20that\x20it\x20was\x20called\x20when\x20executed',
    '182PrGdDE',
    'simplifies\x20access\x20to\x20the\x20arguments\x20for\x20the\x20last\x20(most\x20recent)\x20call',
    '11wtMaAc',
    'allArgs',
    '250091avVVjp'
];
var a24_0x426543 = a24_0x1c80;
function a24_0x1c80(_0x23a93d, _0x2b8449) {
    return a24_0x1c80 = function (_0x3ae696, _0x1c801b) {
        _0x3ae696 = _0x3ae696 - 0x17b;
        var _0x61d30a = a24_0x3ae6[_0x3ae696];
        return _0x61d30a;
    }, a24_0x1c80(_0x23a93d, _0x2b8449);
}
(function (_0x51b9bd, _0x36f948) {
    var _0x4d4ea2 = a24_0x1c80;
    while (!![]) {
        try {
            var _0x310960 = -parseInt(_0x4d4ea2(0x187)) * -parseInt(_0x4d4ea2(0x197)) + parseInt(_0x4d4ea2(0x182)) + -parseInt(_0x4d4ea2(0x191)) + parseInt(_0x4d4ea2(0x195)) * -parseInt(_0x4d4ea2(0x180)) + parseInt(_0x4d4ea2(0x181)) + parseInt(_0x4d4ea2(0x183)) * -parseInt(_0x4d4ea2(0x193)) + -parseInt(_0x4d4ea2(0x17c)) * -parseInt(_0x4d4ea2(0x19a));
            if (_0x310960 === _0x36f948)
                break;
            else
                _0x51b9bd['push'](_0x51b9bd['shift']());
        } catch (_0x1f5bff) {
            _0x51b9bd['push'](_0x51b9bd['shift']());
        }
    }
}(a24_0x3ae6, 0x999db), describe(a24_0x426543(0x18c), function () {
    var _0x55ca17 = a24_0x426543;
    it(_0x55ca17(0x192), function () {
        var _0x8e3227 = _0x55ca17, _0x5ad7df = new jasmineUnderTest[(_0x8e3227(0x18c))]();
        expect(_0x5ad7df[_0x8e3227(0x1a1)]())['toBe'](![]), _0x5ad7df[_0x8e3227(0x184)](), expect(_0x5ad7df['any']())['toBe'](!![]);
    }), it('tracks\x20that\x20number\x20of\x20times\x20that\x20it\x20is\x20executed', function () {
        var _0x1584db = _0x55ca17, _0x3c8156 = new jasmineUnderTest['CallTracker']();
        expect(_0x3c8156[_0x1584db(0x185)]())[_0x1584db(0x18b)](0x0), _0x3c8156[_0x1584db(0x184)](), expect(_0x3c8156[_0x1584db(0x185)]())[_0x1584db(0x18b)](0x1);
    }), it(_0x55ca17(0x17d), function () {
        var _0x6062c1 = _0x55ca17, _0x56e723 = new jasmineUnderTest[(_0x6062c1(0x18c))]();
        _0x56e723['track']({
            'object': void 0x0,
            'args': []
        }), _0x56e723['track']({
            'object': {},
            'args': [
                0x0,
                _0x6062c1(0x199)
            ]
        }), expect(_0x56e723['argsFor'](0x0))[_0x6062c1(0x18b)]([]), expect(_0x56e723[_0x6062c1(0x1a2)](0x1))[_0x6062c1(0x18b)]([
            0x0,
            _0x6062c1(0x199)
        ]);
    }), it(_0x55ca17(0x18e), function () {
        var _0x1a7d14 = _0x55ca17, _0xd1acd6 = new jasmineUnderTest[(_0x1a7d14(0x18c))](), _0x53fb5a = {}, _0x15ddc8 = {};
        _0xd1acd6['track']({
            'object': _0x53fb5a,
            'args': []
        }), _0xd1acd6['track']({
            'object': _0x15ddc8,
            'args': []
        }), _0xd1acd6['track']({ 'args': [] }), expect(_0xd1acd6['thisFor'](0x0))[_0x1a7d14(0x188)](_0x53fb5a), expect(_0xd1acd6[_0x1a7d14(0x198)](0x1))['toBe'](_0x15ddc8), expect(_0xd1acd6[_0x1a7d14(0x198)](0x2))[_0x1a7d14(0x188)](undefined);
    }), it(_0x55ca17(0x19b), function () {
        var _0x51cffd = _0x55ca17, _0x3a9c80 = new jasmineUnderTest[(_0x51cffd(0x18c))]();
        expect(_0x3a9c80[_0x51cffd(0x1a2)](0x0))[_0x51cffd(0x18b)]([]);
    }), it(_0x55ca17(0x190), function () {
        var _0x38f34c = _0x55ca17, _0x4ca36f = new jasmineUnderTest['CallTracker']();
        _0x4ca36f[_0x38f34c(0x184)]({
            'object': {},
            'args': []
        }), _0x4ca36f[_0x38f34c(0x184)]({
            'object': {},
            'args': [
                0x0,
                _0x38f34c(0x199)
            ]
        }), expect(_0x4ca36f[_0x38f34c(0x196)]())[_0x38f34c(0x18b)]([
            [],
            [
                0x0,
                _0x38f34c(0x199)
            ]
        ]);
    }), it('tracks\x20the\x20context\x20and\x20arguments\x20for\x20each\x20call', function () {
        var _0x174e6e = _0x55ca17, _0x718bbc = new jasmineUnderTest[(_0x174e6e(0x18c))]();
        _0x718bbc[_0x174e6e(0x184)]({
            'object': {},
            'args': []
        }), _0x718bbc[_0x174e6e(0x184)]({
            'object': {},
            'args': [
                0x0,
                'foo'
            ]
        }), expect(_0x718bbc[_0x174e6e(0x17b)]()[0x0])[_0x174e6e(0x18b)]({
            'object': {},
            'args': []
        }), expect(_0x718bbc[_0x174e6e(0x17b)]()[0x1])[_0x174e6e(0x18b)]({
            'object': {},
            'args': [
                0x0,
                _0x174e6e(0x199)
            ]
        });
    }), it(_0x55ca17(0x194), function () {
        var _0x20d491 = _0x55ca17, _0x2fe97f = new jasmineUnderTest[(_0x20d491(0x18c))]();
        _0x2fe97f['track'](), _0x2fe97f[_0x20d491(0x184)]({
            'object': {},
            'args': [
                0x0,
                _0x20d491(0x199)
            ]
        }), expect(_0x2fe97f[_0x20d491(0x17f)]())[_0x20d491(0x18b)]({
            'object': {},
            'args': [
                0x0,
                _0x20d491(0x199)
            ]
        });
    }), it(_0x55ca17(0x19f), function () {
        var _0x2d7e1f = _0x55ca17, _0x2bb8cb = new jasmineUnderTest[(_0x2d7e1f(0x18c))]();
        expect(_0x2bb8cb[_0x2d7e1f(0x17f)]())[_0x2d7e1f(0x186)]();
    }), it(_0x55ca17(0x18d), function () {
        var _0x5d4623 = _0x55ca17, _0x2f9bda = new jasmineUnderTest[(_0x5d4623(0x18c))]();
        _0x2f9bda[_0x5d4623(0x184)]({
            'object': {},
            'args': [
                0x0,
                _0x5d4623(0x199)
            ]
        }), expect(_0x2f9bda['first']())[_0x5d4623(0x18b)]({
            'object': {},
            'args': [
                0x0,
                _0x5d4623(0x199)
            ]
        });
    }), it(_0x55ca17(0x17e), function () {
        var _0xa6b2f5 = _0x55ca17, _0x44c0c4 = new jasmineUnderTest[(_0xa6b2f5(0x18c))]();
        expect(_0x44c0c4['first']())['toBeFalsy']();
    }), it(_0x55ca17(0x1a0), function () {
        var _0x30cb5d = _0x55ca17, _0x2b1332 = new jasmineUnderTest[(_0x30cb5d(0x18c))]();
        _0x2b1332['track'](), _0x2b1332[_0x30cb5d(0x184)]({
            'object': {},
            'args': [
                0x0,
                _0x30cb5d(0x199)
            ]
        }), _0x2b1332['reset'](), expect(_0x2b1332['any']())['toBe'](![]), expect(_0x2b1332[_0x30cb5d(0x185)]())['toEqual'](0x0), expect(_0x2b1332[_0x30cb5d(0x1a2)](0x0))['toEqual']([]), expect(_0x2b1332['all']())[_0x30cb5d(0x18b)]([]), expect(_0x2b1332[_0x30cb5d(0x17f)]())[_0x30cb5d(0x186)]();
    }), it(_0x55ca17(0x18a), function () {
        var _0x35238b = _0x55ca17, _0x4a46b0 = new jasmineUnderTest['CallTracker']();
        _0x4a46b0[_0x35238b(0x19d)]();
        var _0xe8dd87 = { 'foo': _0x35238b(0x189) }, _0x380ee6 = [
                _0x35238b(0x199),
                _0x35238b(0x189)
            ];
        _0x4a46b0['track']({
            'object': {},
            'args': [
                _0xe8dd87,
                _0x380ee6,
                ![],
                undefined,
                null,
                NaN,
                '',
                0x0,
                0x1
            ]
        }), expect(_0x4a46b0['mostRecent']()[_0x35238b(0x18f)][0x0])[_0x35238b(0x19c)][_0x35238b(0x188)](_0xe8dd87), expect(_0x4a46b0[_0x35238b(0x17f)]()[_0x35238b(0x18f)][0x0])[_0x35238b(0x18b)](_0xe8dd87), expect(_0x4a46b0[_0x35238b(0x17f)]()[_0x35238b(0x18f)][0x1])[_0x35238b(0x19c)][_0x35238b(0x188)](_0x380ee6), expect(_0x4a46b0[_0x35238b(0x17f)]()[_0x35238b(0x18f)][0x1])[_0x35238b(0x18b)](_0x380ee6);
    }), it(_0x55ca17(0x19e), function () {
        var _0x37d585 = _0x55ca17, _0x4e70b5 = new jasmineUnderTest[(_0x37d585(0x18c))](), _0x52fda0 = [
                undefined,
                null,
                ![],
                '',
                /\s/,
                0x0,
                1.2,
                NaN
            ];
        _0x4e70b5[_0x37d585(0x19d)](), _0x4e70b5['track']({
            'object': {},
            'args': _0x52fda0
        }), expect(_0x4e70b5['mostRecent']()[_0x37d585(0x18f)])['toEqual'](_0x52fda0);
    });
}));