var a63_0x5ac1 = [
    '814523OvsxqT',
    '1CFZMeh',
    '904591LJHaqS',
    'isURL',
    'reject',
    'returns\x20a\x20promise\x20that\x20resolves\x20to\x20false\x20when\x20the\x20promise\x20is\x20rejected',
    '1087984FnjuSm',
    'getEnv',
    'isAsymmetricEqualityTester_',
    '22732UcJmkk',
    '372270hfEcKW',
    'returns\x20a\x20promise\x20that\x20resolves\x20to\x20false\x20when\x20the\x20promise\x20is\x20resolved',
    'returns\x20false\x20when\x20the\x20argument\x27s\x20asymmetricMatch\x20is\x20not\x20a\x20function',
    '771317aBeQtl',
    '464017dfMVfS',
    'getGlobal',
    'undefined',
    'toBe',
    'isSet',
    'returns\x20false\x20when\x20the\x20argument\x20does\x20not\x20have\x20a\x20asymmetricMatch\x20property',
    'requirePromises',
    '1YKrPFn',
    'isError_',
    'returns\x20true\x20when\x20the\x20object\x20is\x20a\x20URL',
    'returns\x20a\x20promise\x20that\x20resolves\x20to\x20true\x20when\x20the\x20promise\x20is\x20pending',
    'returns\x20false\x20when\x20the\x20object\x20is\x20not\x20a\x20URL',
    'toBeResolvedTo',
    '25dTpkFX',
    'yes',
    'WebSocket',
    'http://localhost/',
    'isPending_',
    'requireUrls',
    'base\x20helpers',
    'returns\x20false\x20when\x20the\x20object\x20is\x20not\x20a\x20Set'
];
function a63_0x3cb3(_0x38d3eb, _0x477670) {
    return a63_0x3cb3 = function (_0x5ac1f2, _0x3cb387) {
        _0x5ac1f2 = _0x5ac1f2 - 0x10a;
        var _0x3aa35c = a63_0x5ac1[_0x5ac1f2];
        return _0x3aa35c;
    }, a63_0x3cb3(_0x38d3eb, _0x477670);
}
var a63_0x2ad633 = a63_0x3cb3;
(function (_0x5ef150, _0x1f5d2f) {
    var _0x113207 = a63_0x3cb3;
    while (!![]) {
        try {
            var _0x55894a = -parseInt(_0x113207(0x11f)) * -parseInt(_0x113207(0x117)) + -parseInt(_0x113207(0x118)) + -parseInt(_0x113207(0x10a)) + parseInt(_0x113207(0x10c)) + parseInt(_0x113207(0x110)) + -parseInt(_0x113207(0x113)) * parseInt(_0x113207(0x125)) + parseInt(_0x113207(0x114)) * -parseInt(_0x113207(0x10b));
            if (_0x55894a === _0x1f5d2f)
                break;
            else
                _0x5ef150['push'](_0x5ef150['shift']());
        } catch (_0xd9cd67) {
            _0x5ef150['push'](_0x5ef150['shift']());
        }
    }
}(a63_0x5ac1, 0x8500e), describe(a63_0x2ad633(0x12b), function () {
    var _0x5c21c6 = a63_0x2ad633;
    describe(_0x5c21c6(0x120), function () {
        it('correctly\x20handles\x20WebSocket\x20events', function (_0x3f4745) {
            var _0x4f0002 = a63_0x3cb3;
            if (typeof jasmine[_0x4f0002(0x119)]()[_0x4f0002(0x127)] === _0x4f0002(0x11a)) {
                _0x3f4745();
                return;
            }
            var _0x41f3eb = function () {
                    var _0x44dc67 = new WebSocket('ws://localhost'), _0x3d9565;
                    return _0x44dc67['onerror'] = function (_0x44143) {
                        _0x3d9565 = _0x44143;
                    }, function () {
                        return _0x3d9565;
                    };
                }(), _0x12b058 = 0x14, _0x48a804 = setInterval(function () {
                    var _0x2bea89 = _0x4f0002;
                    if (_0x41f3eb() || _0x12b058 === 0x0) {
                        var _0x24b416 = jasmineUnderTest['isError_'](_0x41f3eb());
                        expect(_0x24b416)[_0x2bea89(0x11b)](![]), clearInterval(_0x48a804), _0x3f4745();
                    } else
                        _0x12b058--;
                }, 0x64);
        });
    }), describe(_0x5c21c6(0x112), function () {
        var _0x29a6e1 = _0x5c21c6;
        it('returns\x20false\x20when\x20the\x20argument\x20is\x20falsy', function () {
            var _0x41f4af = a63_0x3cb3;
            expect(jasmineUnderTest[_0x41f4af(0x112)](null))['toBe'](![]);
        }), it(_0x29a6e1(0x11d), function () {
            var _0x3ac14d = _0x29a6e1, _0xf41e17 = {};
            expect(jasmineUnderTest[_0x3ac14d(0x112)](_0xf41e17))[_0x3ac14d(0x11b)](![]);
        }), it(_0x29a6e1(0x116), function () {
            var _0x593e29 = _0x29a6e1, _0xffcfd7 = { 'asymmetricMatch': _0x593e29(0x126) };
            expect(jasmineUnderTest[_0x593e29(0x112)](_0xffcfd7))[_0x593e29(0x11b)](![]);
        }), it('returns\x20true\x20when\x20the\x20argument\x27s\x20asymmetricMatch\x20is\x20a\x20function', function () {
            var _0x1102f4 = _0x29a6e1, _0x2be8f0 = {
                    'asymmetricMatch': function () {
                    }
                };
            expect(jasmineUnderTest[_0x1102f4(0x112)](_0x2be8f0))[_0x1102f4(0x11b)](!![]);
        });
    }), describe(_0x5c21c6(0x11c), function () {
        var _0x437fb5 = _0x5c21c6;
        it('returns\x20true\x20when\x20the\x20object\x20is\x20a\x20Set', function () {
            var _0x3a80a5 = a63_0x3cb3;
            jasmine[_0x3a80a5(0x111)]()['requireFunctioningSets'](), expect(jasmineUnderTest[_0x3a80a5(0x11c)](new Set()))[_0x3a80a5(0x11b)](!![]);
        }), it(_0x437fb5(0x12c), function () {
            var _0x1e7a82 = _0x437fb5;
            expect(jasmineUnderTest['isSet']({}))[_0x1e7a82(0x11b)](![]);
        });
    }), describe(_0x5c21c6(0x10d), function () {
        var _0x4fc45f = _0x5c21c6;
        it(_0x4fc45f(0x121), function () {
            var _0x80b1a8 = _0x4fc45f;
            jasmine[_0x80b1a8(0x111)]()['requireUrls'](), expect(jasmineUnderTest[_0x80b1a8(0x10d)](new URL(_0x80b1a8(0x128))))[_0x80b1a8(0x11b)](!![]);
        }), it(_0x4fc45f(0x123), function () {
            var _0x3bd9c1 = _0x4fc45f;
            jasmine[_0x3bd9c1(0x111)]()[_0x3bd9c1(0x12a)](), expect(jasmineUnderTest[_0x3bd9c1(0x10d)]({}))[_0x3bd9c1(0x11b)](![]);
        });
    }), describe(_0x5c21c6(0x129), function () {
        var _0x19a4f9 = _0x5c21c6;
        it(_0x19a4f9(0x122), function () {
            var _0x25998e = _0x19a4f9;
            jasmine[_0x25998e(0x111)]()[_0x25998e(0x11e)]();
            var _0x26b974 = new Promise(function () {
            });
            return expectAsync(jasmineUnderTest['isPending_'](_0x26b974))[_0x25998e(0x124)](!![]);
        }), it(_0x19a4f9(0x115), function () {
            var _0x29daba = _0x19a4f9;
            jasmine[_0x29daba(0x111)]()[_0x29daba(0x11e)]();
            var _0x2e8605 = Promise['resolve']();
            return expectAsync(jasmineUnderTest[_0x29daba(0x129)](_0x2e8605))[_0x29daba(0x124)](![]);
        }), it(_0x19a4f9(0x10f), function () {
            var _0x67853f = _0x19a4f9;
            jasmine[_0x67853f(0x111)]()[_0x67853f(0x11e)]();
            var _0x54c283 = Promise[_0x67853f(0x10e)]();
            return expectAsync(jasmineUnderTest['isPending_'](_0x54c283))[_0x67853f(0x124)](![]);
        });
    });
}));