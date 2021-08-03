var a66_0x5c47 = [
    'matcherFactorySpy',
    'message',
    'passes\x20the\x20spec\x20if\x20the\x20custom\x20async\x20matcher\x20passes',
    'failedExpectations',
    'provides\x20custom\x20equality\x20testers\x20to\x20the\x20matcher\x20factory\x20via\x20matchersUtil',
    '124021gPvuSF',
    'status',
    'configure',
    'toBeReal',
    'uses\x20the\x20negative\x20compare\x20function\x20for\x20a\x20negative\x20comparison,\x20if\x20provided',
    'callFake',
    'toHaveBeenCalledWith',
    '779409hESsRy',
    'spec\x20using\x20custom\x20async\x20matcher',
    'resolve',
    '101741XVGoAW',
    'Expected\x20\x27a\x27\x20to\x20be\x20real.',
    '1108099aRJIoC',
    'getEnv',
    'generates\x20messages\x20with\x20the\x20same\x20rules\x20as\x20built\x20in\x20matchers\x20absent\x20a\x20custom\x20message',
    'expectAsync',
    'requirePromises',
    'cleanup_',
    'addReporter',
    'passed',
    'passes\x20the\x20jasmine\x20utility\x20and\x20current\x20equality\x20testers\x20to\x20the\x20matcher\x20factory',
    'createSpy',
    '685798UsGmgW',
    '4YzoYry',
    '871680OhBooS',
    'spec\x20with\x20an\x20expectation',
    '749228AHRMhx',
    'toEqual',
    'MatchersUtil',
    'spec\x20with\x20custom\x20negative\x20comparison\x20matcher',
    'and',
    'execute',
    '7mRlQJg',
    'any',
    'spec\x20with\x20expectation',
    'addAsyncMatchers'
];
function a66_0x47f6(_0x4cd681, _0xbbbbca) {
    return a66_0x47f6 = function (_0x5c47a2, _0x47f6d4) {
        _0x5c47a2 = _0x5c47a2 - 0x6d;
        var _0x16f881 = a66_0x5c47[_0x5c47a2];
        return _0x16f881;
    }, a66_0x47f6(_0x4cd681, _0xbbbbca);
}
(function (_0x168287, _0x4f9898) {
    var _0x5352ee = a66_0x47f6;
    while (!![]) {
        try {
            var _0x5968ee = parseInt(_0x5352ee(0x77)) + parseInt(_0x5352ee(0x79)) + parseInt(_0x5352ee(0x78)) * -parseInt(_0x5352ee(0x8a)) + parseInt(_0x5352ee(0x91)) + -parseInt(_0x5352ee(0x94)) * -parseInt(_0x5352ee(0x81)) + -parseInt(_0x5352ee(0x7b)) + -parseInt(_0x5352ee(0x6d));
            if (_0x5968ee === _0x4f9898)
                break;
            else
                _0x168287['push'](_0x168287['shift']());
        } catch (_0x5ee20a) {
            _0x168287['push'](_0x168287['shift']());
        }
    }
}(a66_0x5c47, 0xa9d6f), describe('Custom\x20Async\x20Matchers\x20(Integration)', function () {
    var _0x5ab77d = a66_0x47f6, _0x19eac9;
    beforeEach(function () {
        var _0x1b416b = a66_0x47f6;
        _0x19eac9 = new jasmineUnderTest['Env'](), _0x19eac9[_0x1b416b(0x8c)]({ 'random': ![] });
    }), afterEach(function () {
        var _0x2dbdda = a66_0x47f6;
        _0x19eac9[_0x2dbdda(0x72)]();
    }), it(_0x5ab77d(0x87), function (_0x1f575a) {
        var _0x4fa528 = _0x5ab77d;
        jasmine['getEnv']()[_0x4fa528(0x71)](), _0x19eac9['it'](_0x4fa528(0x92), function () {
            var _0x440506 = _0x4fa528;
            return _0x19eac9['addAsyncMatchers']({
                'toBeReal': function () {
                    return {
                        'compare': function () {
                            return Promise['resolve']({ 'pass': !![] });
                        }
                    };
                }
            }), _0x19eac9[_0x440506(0x70)](!![])['toBeReal']();
        });
        var _0x126faa = function (_0x596a19) {
            var _0x4a35be = _0x4fa528;
            expect(_0x596a19['status'])[_0x4a35be(0x7c)](_0x4a35be(0x74));
        };
        _0x19eac9[_0x4fa528(0x73)]({ 'specDone': _0x126faa }), _0x19eac9['execute'](null, _0x1f575a);
    }), it(_0x5ab77d(0x8e), function (_0x5335f7) {
        var _0x21e90b = _0x5ab77d;
        jasmine['getEnv']()['requirePromises'](), _0x19eac9['it'](_0x21e90b(0x7e), function () {
            var _0x34664a = _0x21e90b;
            return _0x19eac9[_0x34664a(0x84)]({
                'toBeReal': function () {
                    return {
                        'compare': function () {
                            var _0x3959c1 = a66_0x47f6;
                            return Promise[_0x3959c1(0x93)]({ 'pass': !![] });
                        },
                        'negativeCompare': function () {
                            var _0x12be3b = a66_0x47f6;
                            return Promise[_0x12be3b(0x93)]({ 'pass': !![] });
                        }
                    };
                }
            }), _0x19eac9[_0x34664a(0x70)](!![])['not'][_0x34664a(0x8d)]();
        });
        var _0x22230c = function (_0x45d6c1) {
            var _0x3fd282 = _0x21e90b;
            expect(_0x45d6c1[_0x3fd282(0x8b)])[_0x3fd282(0x7c)]('passed');
        };
        _0x19eac9[_0x21e90b(0x73)]({ 'specDone': _0x22230c }), _0x19eac9[_0x21e90b(0x80)](null, _0x5335f7);
    }), it(_0x5ab77d(0x6f), function (_0x2bd04f) {
        var _0x8350c6 = _0x5ab77d;
        jasmine[_0x8350c6(0x6e)]()['requirePromises'](), _0x19eac9['it'](_0x8350c6(0x7a), function () {
            var _0x40dfa8 = _0x8350c6;
            return _0x19eac9[_0x40dfa8(0x84)]({
                'toBeReal': function () {
                    return {
                        'compare': function () {
                            var _0x311c62 = a66_0x47f6;
                            return Promise[_0x311c62(0x93)]({ 'pass': ![] });
                        }
                    };
                }
            }), _0x19eac9['expectAsync']('a')[_0x40dfa8(0x8d)]();
        });
        var _0x27c4bd = function (_0x12636b) {
            var _0x43f486 = _0x8350c6;
            expect(_0x12636b[_0x43f486(0x88)][0x0][_0x43f486(0x86)])['toEqual'](_0x43f486(0x95));
        };
        _0x19eac9['addReporter']({ 'specDone': _0x27c4bd }), _0x19eac9[_0x8350c6(0x80)](null, _0x2bd04f);
    }), it(_0x5ab77d(0x75), function (_0x50f6b9) {
        var _0x16851a = _0x5ab77d;
        jasmine[_0x16851a(0x6e)]()[_0x16851a(0x71)]();
        var _0x549889 = function () {
                return {
                    'compare': function () {
                        var _0x4251d8 = a66_0x47f6;
                        return Promise[_0x4251d8(0x93)]({ 'pass': !![] });
                    }
                };
            }, _0x550a36 = jasmine[_0x16851a(0x76)](_0x16851a(0x85))[_0x16851a(0x7f)][_0x16851a(0x8f)](_0x549889), _0x1fc64a = function () {
                return !![];
            };
        _0x19eac9['it'](_0x16851a(0x83), function () {
            var _0x223167 = _0x16851a;
            return _0x19eac9['addCustomEqualityTester'](_0x1fc64a), _0x19eac9[_0x223167(0x84)]({ 'toBeReal': _0x550a36 }), _0x19eac9['expectAsync'](!![])['toBeReal']();
        });
        var _0x479cb1 = function () {
            var _0x11c19b = _0x16851a;
            expect(_0x550a36)[_0x11c19b(0x90)](jasmine[_0x11c19b(0x82)](jasmineUnderTest[_0x11c19b(0x7d)]), [_0x1fc64a]);
        };
        _0x19eac9[_0x16851a(0x73)]({ 'specDone': _0x479cb1 }), _0x19eac9[_0x16851a(0x80)](null, _0x50f6b9);
    }), it(_0x5ab77d(0x89), function (_0x2b8375) {
        var _0x46d338 = _0x5ab77d;
        jasmine[_0x46d338(0x6e)]()[_0x46d338(0x71)]();
        var _0xcf0719 = function (_0x1509b1) {
                return {
                    'compare': function (_0x82e67c, _0x8e1ecd) {
                        var _0x1f782e = a66_0x47f6;
                        return Promise[_0x1f782e(0x93)]({ 'pass': _0x1509b1['equals'](_0x82e67c[0x0], _0x8e1ecd) });
                    }
                };
            }, _0x4d62e1 = jasmine['createSpy']('customEqualityFn')[_0x46d338(0x7f)]['callFake'](function (_0x463d7f, _0x45e1c0) {
                return _0x463d7f['toString']() === _0x45e1c0;
            });
        _0x19eac9['it'](_0x46d338(0x83), function () {
            var _0x18c713 = _0x46d338;
            return _0x19eac9['addCustomEqualityTester'](_0x4d62e1), _0x19eac9[_0x18c713(0x84)]({ 'toBeArrayWithFirstElement': _0xcf0719 }), _0x19eac9[_0x18c713(0x70)]([
                0x1,
                0x2
            ])['toBeArrayWithFirstElement']('1');
        });
        var _0x3def12 = function (_0x51fa4a) {
            var _0x5b5ab4 = _0x46d338;
            expect(_0x4d62e1)[_0x5b5ab4(0x90)](0x1, '1'), expect(_0x51fa4a[_0x5b5ab4(0x88)])[_0x5b5ab4(0x7c)]([]);
        };
        _0x19eac9['addReporter']({ 'specDone': _0x3def12 }), _0x19eac9[_0x46d338(0x80)](null, _0x2b8375);
    });
}));