var a45_0x127f = [
    '1114643ZNkLTD',
    'timer',
    'createSpyObj',
    'startTimer',
    '1VFnhKd',
    'retrieves\x20a\x20result\x20with\x20pending\x20status',
    '1393nYfXnm',
    'cleanup_',
    'Env',
    'status',
    'insideAfterEach',
    'I\x20am\x20a\x20suite',
    'result',
    'passed',
    'duration',
    'returns\x20a\x20UserContext',
    'getResult',
    'onException',
    'afterEach',
    'constructor',
    'adds\x20before\x20functions\x20in\x20order\x20of\x20needed\x20execution',
    'Suite',
    'outerAfterEach',
    'failed',
    'addExpectationResult',
    'pend',
    'UserContext',
    '321941ZtUUbS',
    'retrieves\x20a\x20result\x20with\x20updated\x20status',
    'failedExpectations',
    '613625HijVrL',
    'suite',
    'endTimer',
    'insideBeforeEach',
    '22PDFVLe',
    '#sharedUserContext',
    'beforeEach',
    'calls\x20timer\x20to\x20compute\x20duration',
    'sharedUserContext',
    'beforeFns',
    '379KdwmKd',
    '7094VKGlcb',
    'toEqual',
    '1blAGid',
    'I\x20am\x20a\x20parent\x20suite',
    'errors',
    'adds\x20after\x20functions\x20in\x20order\x20of\x20needed\x20execution',
    'I\x20am\x20a\x20parent\x20suite\x20I\x20am\x20a\x20suite',
    '3962558PGQLzp',
    '563365kHMzQD',
    'getFullName',
    'pretend\x20top\x20level\x20suite',
    'createSpy',
    'toBe',
    'returns\x20its\x20full\x20name\x20when\x20it\x20has\x20parent\x20suites',
    'ExpectationFailed'
];
var a45_0x2f7e8d = a45_0x5da3;
function a45_0x5da3(_0x495ad0, _0x3aa9f6) {
    return a45_0x5da3 = function (_0x127f1d, _0x5da3d6) {
        _0x127f1d = _0x127f1d - 0xaf;
        var _0x16fe2b = a45_0x127f[_0x127f1d];
        return _0x16fe2b;
    }, a45_0x5da3(_0x495ad0, _0x3aa9f6);
}
(function (_0x5824cb, _0x9f7e4c) {
    var _0x1a909d = a45_0x5da3;
    while (!![]) {
        try {
            var _0x5a477b = -parseInt(_0x1a909d(0xbb)) * parseInt(_0x1a909d(0xc2)) + -parseInt(_0x1a909d(0xb7)) + parseInt(_0x1a909d(0xd7)) * -parseInt(_0x1a909d(0xc1)) + -parseInt(_0x1a909d(0xc4)) * parseInt(_0x1a909d(0xb4)) + parseInt(_0x1a909d(0xd1)) * -parseInt(_0x1a909d(0xd5)) + -parseInt(_0x1a909d(0xca)) + parseInt(_0x1a909d(0xc9));
            if (_0x5a477b === _0x9f7e4c)
                break;
            else
                _0x5824cb['push'](_0x5824cb['shift']());
        } catch (_0x5e2747) {
            _0x5824cb['push'](_0x5824cb['shift']());
        }
    }
}(a45_0x127f, 0xa2589), describe(a45_0x2f7e8d(0xe6), function () {
    var _0x109449 = a45_0x2f7e8d, _0x4a7b64;
    beforeEach(function () {
        var _0x4967ff = a45_0x5da3;
        _0x4a7b64 = new jasmineUnderTest[(_0x4967ff(0xd9))]();
    }), afterEach(function () {
        var _0x4640a3 = a45_0x5da3;
        _0x4a7b64[_0x4640a3(0xd8)]();
    }), it('keeps\x20its\x20id', function () {
        var _0x49f1f5 = a45_0x5da3, _0x405daf = new jasmineUnderTest[(_0x49f1f5(0xe6))]({
                'env': _0x4a7b64,
                'id': 0x1c8,
                'description': 'I\x20am\x20a\x20suite'
            });
        expect(_0x405daf['id'])[_0x49f1f5(0xc3)](0x1c8);
    }), it('returns\x20blank\x20full\x20name\x20for\x20top\x20level\x20suite', function () {
        var _0x420df1 = a45_0x5da3, _0x1fe2a0 = new jasmineUnderTest[(_0x420df1(0xe6))]({
                'env': _0x4a7b64,
                'description': 'I\x20am\x20a\x20suite'
            });
        expect(_0x1fe2a0[_0x420df1(0xcb)]())[_0x420df1(0xc3)]('');
    }), it(_0x109449(0xcf), function () {
        var _0x22ad7b = _0x109449, _0x50e225 = new jasmineUnderTest[(_0x22ad7b(0xe6))]({
                'env': _0x4a7b64,
                'description': _0x22ad7b(0xc5),
                'parentSuite': jasmine[_0x22ad7b(0xcd)](_0x22ad7b(0xcc))
            }), _0x12a4cd = new jasmineUnderTest['Suite']({
                'env': _0x4a7b64,
                'description': _0x22ad7b(0xdc),
                'parentSuite': _0x50e225
            });
        expect(_0x12a4cd[_0x22ad7b(0xcb)]())[_0x22ad7b(0xc3)](_0x22ad7b(0xc8));
    }), it(_0x109449(0xe5), function () {
        var _0x52e65d = _0x109449, _0x3955d2 = new jasmineUnderTest[(_0x52e65d(0xe6))]({
                'env': _0x4a7b64,
                'description': _0x52e65d(0xdc)
            }), _0x3e9daf = jasmine[_0x52e65d(0xcd)]('outerBeforeEach'), _0x5ad146 = jasmine[_0x52e65d(0xcd)](_0x52e65d(0xba));
        _0x3955d2[_0x52e65d(0xbd)](_0x3e9daf), _0x3955d2[_0x52e65d(0xbd)](_0x5ad146), expect(_0x3955d2[_0x52e65d(0xc0)])[_0x52e65d(0xc3)]([
            _0x5ad146,
            _0x3e9daf
        ]);
    }), it(_0x109449(0xc7), function () {
        var _0x316f9c = _0x109449, _0x5cd7c4 = new jasmineUnderTest[(_0x316f9c(0xe6))]({
                'env': _0x4a7b64,
                'description': 'I\x20am\x20a\x20suite'
            }), _0x450c4f = jasmine[_0x316f9c(0xcd)](_0x316f9c(0xaf)), _0x589dbc = jasmine[_0x316f9c(0xcd)](_0x316f9c(0xdb));
        _0x5cd7c4[_0x316f9c(0xe3)](_0x450c4f), _0x5cd7c4[_0x316f9c(0xe3)](_0x589dbc), expect(_0x5cd7c4['afterFns'])[_0x316f9c(0xc3)]([
            _0x589dbc,
            _0x450c4f
        ]);
    }), it('has\x20a\x20status\x20of\x20failed\x20if\x20any\x20expectations\x20have\x20failed', function () {
        var _0x4f50a6 = _0x109449, _0x5639cf = new jasmineUnderTest[(_0x4f50a6(0xe6))]({
                'expectationResultFactory': function () {
                    return 'hi';
                }
            });
        _0x5639cf[_0x4f50a6(0xb1)](![]), expect(_0x5639cf[_0x4f50a6(0xda)]())[_0x4f50a6(0xce)](_0x4f50a6(0xb0));
    }), it(_0x109449(0xb5), function () {
        var _0x1854f3 = _0x109449, _0x29d16a = new jasmineUnderTest[(_0x1854f3(0xe6))]({});
        expect(_0x29d16a[_0x1854f3(0xe1)]()[_0x1854f3(0xda)])['toBe'](_0x1854f3(0xde));
    }), it(_0x109449(0xd6), function () {
        var _0xcca750 = _0x109449, _0x106230 = new jasmineUnderTest[(_0xcca750(0xe6))]({});
        _0x106230[_0xcca750(0xb2)](), expect(_0x106230['getResult']()['status'])[_0xcca750(0xce)]('pending');
    }), it('throws\x20an\x20ExpectationFailed\x20when\x20receiving\x20a\x20failed\x20expectation\x20when\x20throwOnExpectationFailure\x20is\x20set', function () {
        var _0x42a601 = _0x109449, _0x271a96 = new jasmineUnderTest[(_0x42a601(0xe6))]({
                'expectationResultFactory': function (_0x144956) {
                    return _0x144956;
                },
                'throwOnExpectationFailure': !![]
            });
        expect(function () {
            var _0x432ab6 = _0x42a601;
            _0x271a96['addExpectationResult'](![], _0x432ab6(0xb0));
        })['toThrowError'](jasmineUnderTest[_0x42a601(0xc6)][_0x42a601(0xd0)]), expect(_0x271a96[_0x42a601(0xda)]())[_0x42a601(0xce)](_0x42a601(0xb0)), expect(_0x271a96[_0x42a601(0xdd)][_0x42a601(0xb6)])[_0x42a601(0xc3)]([_0x42a601(0xb0)]);
    }), it('does\x20not\x20add\x20an\x20additional\x20failure\x20when\x20an\x20expectation\x20fails', function () {
        var _0x23ccef = _0x109449, _0x1de495 = new jasmineUnderTest[(_0x23ccef(0xe6))]({});
        _0x1de495[_0x23ccef(0xe2)](new jasmineUnderTest['errors'][(_0x23ccef(0xd0))]()), expect(_0x1de495['getResult']()['failedExpectations'])[_0x23ccef(0xc3)]([]);
    }), it(_0x109449(0xbe), function () {
        var _0x143bee = _0x109449, _0x3274b4 = new jasmineUnderTest[(_0x143bee(0xe6))]({
                'env': _0x4a7b64,
                'id': 0x1c8,
                'description': _0x143bee(0xdc),
                'timer': jasmine[_0x143bee(0xd3)](_0x143bee(0xd2), {
                    'start': null,
                    'elapsed': 0x12cc8
                })
            });
        _0x3274b4[_0x143bee(0xd4)](), _0x3274b4[_0x143bee(0xb9)](), expect(_0x3274b4['getResult']()[_0x143bee(0xdf)])[_0x143bee(0xc3)](0x12cc8);
    }), describe(_0x109449(0xbc), function () {
        var _0x25d657 = _0x109449;
        beforeEach(function () {
            var _0x44dd93 = a45_0x5da3;
            this[_0x44dd93(0xb8)] = new jasmineUnderTest[(_0x44dd93(0xe6))]({});
        }), it(_0x25d657(0xe0), function () {
            var _0x487488 = _0x25d657;
            expect(this[_0x487488(0xb8)][_0x487488(0xbf)]()[_0x487488(0xe4)])['toBe'](jasmineUnderTest[_0x487488(0xb3)]);
        });
    });
}));