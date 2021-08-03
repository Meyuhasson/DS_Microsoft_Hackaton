var a36_0x252a = [
    'can\x20accept\x20a\x20date\x20as\x20time\x20base\x20when\x20installing',
    'tick',
    '539784pwLeWk',
    'replaces\x20the\x20global\x20Date\x20when\x20it\x20is\x20installed',
    'allows\x20to\x20increase\x200\x20milliseconds\x20using\x20tick',
    '1OGFFex',
    'toEqual',
    'toBe',
    'toThrow',
    'toThrowError',
    'global\x20Date',
    'MockDate',
    'now',
    'install',
    'copies\x20all\x20Date\x20properties\x20to\x20the\x20mocked\x20date',
    'allows\x20creation\x20of\x20a\x20Date\x20in\x20a\x20different\x20time\x20than\x20the\x20mocked\x20time',
    'makes\x20real\x20dates',
    'does\x20not\x20fail\x20if\x20no\x20global\x20date\x20is\x20found',
    'allows\x20creation\x20of\x20a\x20Date\x20that\x20isn\x27t\x20fully\x20specified',
    'uninstall',
    'Date',
    'and',
    'toHaveBeenCalledWith',
    '20613ZoSXDl',
    'any',
    'createSpy',
    '144538bbRgTH',
    'not',
    'callFake',
    '5prsmpB',
    'calls',
    'getTime',
    '6ZTLrVL',
    '1246724FeIWdI',
    '561766bimzph',
    'takes\x20the\x20current\x20time\x20as\x20the\x20base\x20when\x20installing\x20without\x20parameters',
    '156446rIynCo',
    '1AeLVqL',
    'makes\x20time\x20passes\x20using\x20tick',
    '842500nzngbd',
    'UTC'
];
function a36_0x759d(_0x290819, _0x10d4c3) {
    return a36_0x759d = function (_0x252ac8, _0x759d0a) {
        _0x252ac8 = _0x252ac8 - 0x1b5;
        var _0x4e9b35 = a36_0x252a[_0x252ac8];
        return _0x4e9b35;
    }, a36_0x759d(_0x290819, _0x10d4c3);
}
(function (_0x20fce5, _0x53df1f) {
    var _0x318abb = a36_0x759d;
    while (!![]) {
        try {
            var _0x4a3ee7 = -parseInt(_0x318abb(0x1c8)) * -parseInt(_0x318abb(0x1d6)) + parseInt(_0x318abb(0x1d8)) + parseInt(_0x318abb(0x1d3)) + parseInt(_0x318abb(0x1cb)) * -parseInt(_0x318abb(0x1d1)) + parseInt(_0x318abb(0x1dc)) + parseInt(_0x318abb(0x1d2)) * -parseInt(_0x318abb(0x1b6)) + parseInt(_0x318abb(0x1d5)) * parseInt(_0x318abb(0x1ce));
            if (_0x4a3ee7 === _0x53df1f)
                break;
            else
                _0x20fce5['push'](_0x20fce5['shift']());
        } catch (_0x1cf582) {
            _0x20fce5['push'](_0x20fce5['shift']());
        }
    }
}(a36_0x252a, 0x9a86d), describe('FakeDate', function () {
    var _0x40b4de = a36_0x759d;
    it(_0x40b4de(0x1c2), function () {
        var _0x27135f = _0x40b4de, _0x400a24 = {}, _0x16da24 = new jasmineUnderTest[(_0x27135f(0x1bc))](_0x400a24);
        expect(function () {
            var _0x114210 = _0x27135f;
            _0x16da24[_0x114210(0x1be)](), _0x16da24[_0x114210(0x1db)](0x0), _0x16da24[_0x114210(0x1c4)]();
        })[_0x27135f(0x1cc)][_0x27135f(0x1b9)]();
    }), it(_0x40b4de(0x1dd), function () {
        var _0x3835cd = _0x40b4de, _0x5bebd5 = jasmine[_0x3835cd(0x1ca)](_0x3835cd(0x1bb))['and']['callFake'](function () {
                return {
                    'getTime': function () {
                    }
                };
            }), _0x10b608 = { 'Date': _0x5bebd5 }, _0x468725 = new jasmineUnderTest['MockDate'](_0x10b608);
        expect(_0x10b608[_0x3835cd(0x1c5)])[_0x3835cd(0x1b7)](_0x5bebd5), _0x468725[_0x3835cd(0x1be)](), expect(_0x10b608[_0x3835cd(0x1c5)])[_0x3835cd(0x1cc)][_0x3835cd(0x1b7)](_0x5bebd5);
    }), it('replaces\x20the\x20global\x20Date\x20on\x20uninstall', function () {
        var _0x38613c = _0x40b4de, _0xd815 = jasmine['createSpy'](_0x38613c(0x1bb))[_0x38613c(0x1c6)][_0x38613c(0x1cd)](function () {
                return {
                    'getTime': function () {
                    }
                };
            }), _0x9e610d = { 'Date': _0xd815 }, _0x533e82 = new jasmineUnderTest[(_0x38613c(0x1bc))](_0x9e610d);
        _0x533e82[_0x38613c(0x1be)](), _0x533e82[_0x38613c(0x1c4)](), expect(_0x9e610d[_0x38613c(0x1c5)])[_0x38613c(0x1b7)](_0xd815);
    }), it(_0x40b4de(0x1d4), function () {
        var _0x25a207 = _0x40b4de, _0xfad958 = jasmine[_0x25a207(0x1ca)](_0x25a207(0x1bb))[_0x25a207(0x1c6)][_0x25a207(0x1cd)](function () {
                return {
                    'getTime': function () {
                        return 0x3e8;
                    }
                };
            }), _0x5ce828 = { 'Date': _0xfad958 }, _0x36763e = new jasmineUnderTest[(_0x25a207(0x1bc))](_0x5ce828);
        _0x36763e[_0x25a207(0x1be)](), _0xfad958[_0x25a207(0x1cf)]['reset'](), new _0x5ce828[(_0x25a207(0x1c5))](), expect(_0xfad958)[_0x25a207(0x1c7)](0x3e8);
    }), it(_0x40b4de(0x1da), function () {
        var _0x4b32fa = _0x40b4de, _0x180f6c = { 'Date': Date }, _0x236c7d = new jasmineUnderTest[(_0x4b32fa(0x1bc))](_0x180f6c), _0x469f25 = new Date();
        spyOn(_0x469f25, _0x4b32fa(0x1d0))[_0x4b32fa(0x1c6)]['returnValue'](0x7b), _0x236c7d[_0x4b32fa(0x1be)](_0x469f25), expect(new _0x180f6c[(_0x4b32fa(0x1c5))]()[_0x4b32fa(0x1d0)]())[_0x4b32fa(0x1b7)](0x7b);
    }), it(_0x40b4de(0x1c1), function () {
        var _0x3fbcac = _0x40b4de, _0x12563c = { 'Date': Date }, _0x19694d = new jasmineUnderTest[(_0x3fbcac(0x1bc))](_0x12563c);
        _0x19694d[_0x3fbcac(0x1be)](), expect(new _0x12563c[(_0x3fbcac(0x1c5))]())[_0x3fbcac(0x1b7)](jasmine[_0x3fbcac(0x1c9)](Date)), expect(new _0x12563c['Date']() instanceof _0x12563c['Date'])[_0x3fbcac(0x1b8)](!![]);
    }), it('fakes\x20current\x20time\x20when\x20using\x20Date.now()', function () {
        var _0x2204eb = _0x40b4de, _0x5a3254 = jasmine[_0x2204eb(0x1ca)](_0x2204eb(0x1bb))[_0x2204eb(0x1c6)]['callFake'](function () {
                return {
                    'getTime': function () {
                        return 0x3e8;
                    }
                };
            }), _0x3f5ebb = { 'Date': _0x5a3254 };
        _0x5a3254['now'] = function () {
        };
        var _0xdbdf60 = new jasmineUnderTest[(_0x2204eb(0x1bc))](_0x3f5ebb);
        _0xdbdf60[_0x2204eb(0x1be)](), expect(_0x3f5ebb[_0x2204eb(0x1c5)][_0x2204eb(0x1bd)]())[_0x2204eb(0x1b7)](0x3e8);
    }), it('does\x20not\x20stub\x20Date.now()\x20if\x20it\x20doesn\x27t\x20already\x20exist', function () {
        var _0x4df00a = _0x40b4de, _0x360ff0 = jasmine[_0x4df00a(0x1ca)](_0x4df00a(0x1bb))['and'][_0x4df00a(0x1cd)](function () {
                return {
                    'getTime': function () {
                        return 0x3e8;
                    }
                };
            }), _0x23fb60 = { 'Date': _0x360ff0 }, _0x1da173 = new jasmineUnderTest[(_0x4df00a(0x1bc))](_0x23fb60);
        _0x1da173[_0x4df00a(0x1be)](), expect(_0x23fb60[_0x4df00a(0x1c5)][_0x4df00a(0x1bd)])[_0x4df00a(0x1ba)]('Browser\x20does\x20not\x20support\x20Date.now()');
    }), it(_0x40b4de(0x1d7), function () {
        var _0x568533 = _0x40b4de, _0x11ee02 = jasmine[_0x568533(0x1ca)](_0x568533(0x1bb))[_0x568533(0x1c6)][_0x568533(0x1cd)](function () {
                return {
                    'getTime': function () {
                        return 0x3e8;
                    }
                };
            }), _0x18062c = { 'Date': _0x11ee02 };
        _0x11ee02['now'] = function () {
        };
        var _0x529f0b = new jasmineUnderTest[(_0x568533(0x1bc))](_0x18062c);
        _0x529f0b['install'](), _0x529f0b[_0x568533(0x1db)](0x64), expect(_0x18062c[_0x568533(0x1c5)][_0x568533(0x1bd)]())['toEqual'](0x44c), _0x529f0b[_0x568533(0x1db)](0x3e8), expect(_0x18062c[_0x568533(0x1c5)][_0x568533(0x1bd)]())[_0x568533(0x1b7)](0x834);
    }), it(_0x40b4de(0x1b5), function () {
        var _0x16b88d = _0x40b4de, _0x23cd80 = jasmine[_0x16b88d(0x1ca)](_0x16b88d(0x1bb))[_0x16b88d(0x1c6)]['callFake'](function () {
                return {
                    'getTime': function () {
                        return 0x3e8;
                    }
                };
            }), _0x175785 = { 'Date': _0x23cd80 };
        _0x23cd80['now'] = function () {
        };
        var _0x46ec61 = new jasmineUnderTest[(_0x16b88d(0x1bc))](_0x175785);
        _0x46ec61[_0x16b88d(0x1be)](), _0x46ec61[_0x16b88d(0x1db)](0x0), expect(_0x175785[_0x16b88d(0x1c5)]['now']())[_0x16b88d(0x1b7)](0x3e8), _0x46ec61[_0x16b88d(0x1db)](), expect(_0x175785[_0x16b88d(0x1c5)][_0x16b88d(0x1bd)]())['toEqual'](0x3e8);
    }), it(_0x40b4de(0x1c0), function () {
        var _0x2f4c9c = _0x40b4de, _0x355bed = { 'Date': Date }, _0x5d7b38 = new jasmineUnderTest[(_0x2f4c9c(0x1bc))](_0x355bed);
        _0x5d7b38[_0x2f4c9c(0x1be)]();
        var _0x584a4a = new _0x355bed[(_0x2f4c9c(0x1c5))](0x7dd, 0x9, 0x17, 0x0, 0x0, 0x1, 0x0);
        expect(_0x584a4a[_0x2f4c9c(0x1d0)]())[_0x2f4c9c(0x1b7)](new Date(0x7dd, 0x9, 0x17, 0x0, 0x0, 0x1, 0x0)['getTime']());
    }), it(_0x40b4de(0x1c3), function () {
        var _0x13233d = _0x40b4de, _0x25bbc5 = { 'Date': Date }, _0x3807a2 = new jasmineUnderTest[(_0x13233d(0x1bc))](_0x25bbc5);
        _0x3807a2['install']();
        var _0x29821c = new _0x25bbc5[(_0x13233d(0x1c5))](0x7dd, 0x9, 0x17);
        expect(_0x29821c[_0x13233d(0x1d0)]())[_0x13233d(0x1b7)](new Date(0x7dd, 0x9, 0x17)[_0x13233d(0x1d0)]());
    }), it('allows\x20creation\x20of\x20a\x20Date\x20with\x20millis', function () {
        var _0x262704 = _0x40b4de, _0x609589 = { 'Date': Date }, _0x2635d = new jasmineUnderTest[(_0x262704(0x1bc))](_0x609589), _0x37b236 = new Date(0x7de, 0x3, 0xf)[_0x262704(0x1d0)]();
        _0x2635d[_0x262704(0x1be)]();
        var _0x3d0539 = new _0x609589['Date'](_0x37b236);
        expect(_0x3d0539['getTime']())[_0x262704(0x1b7)](_0x37b236);
    }), it(_0x40b4de(0x1bf), function () {
        var _0x62b46b = _0x40b4de, _0x363038 = { 'Date': Date }, _0xfc5f05 = new jasmineUnderTest['MockDate'](_0x363038);
        _0xfc5f05['install'](), expect(_0x363038[_0x62b46b(0x1c5)][_0x62b46b(0x1d9)](0x7dd, 0x9, 0x17))[_0x62b46b(0x1b7)](Date[_0x62b46b(0x1d9)](0x7dd, 0x9, 0x17));
    });
}));