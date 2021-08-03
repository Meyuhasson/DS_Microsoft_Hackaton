var a26_0x3231 = [
    'does\x20not\x20replace\x20clearInterval\x20until\x20it\x20is\x20installed',
    'Date',
    'correctly\x20schedules\x20functions\x20scheduled\x20while\x20the\x20Clock\x20is\x20advancing\x20but\x20after\x20the\x20Clock\x20is\x20uninstalled',
    'uninstall',
    'count',
    '1451etCHih',
    'clears\x20the\x20scheduled\x20function\x20with\x20the\x20scheduler',
    'removeFunctionWithId',
    'mocks\x20the\x20Date\x20object\x20and\x20sets\x20it\x20to\x20current\x20time',
    'mocks\x20the\x20Date\x20object\x20and\x20updates\x20the\x20date\x20per\x20delayed\x20function',
    'withMock',
    'toThrow',
    'toEqual',
    'toHaveBeenCalled',
    'mockDate',
    'foo',
    'Clock',
    'spy',
    '249530YXgSZn',
    'does\x20not\x20mock\x20the\x20Date\x20object\x20by\x20default',
    'scheduleFunction',
    '964645crdCSS',
    '284947udhMet',
    'getTime',
    'schedules\x20the\x20delayed\x20function\x20(via\x20setTimeout)\x20with\x20the\x20fake\x20timer',
    'global\x20clearTimeout',
    'delayedFn3',
    'createSpyObj',
    'global\x20setTimeout',
    'delayedFn1',
    'oops',
    'setInterval',
    '1yGooRm',
    'does\x20not\x20install\x20if\x20the\x20current\x20clearInterval\x20is\x20not\x20the\x20original\x20function\x20on\x20the\x20global',
    '1390703itLzgc',
    'install',
    'toBe',
    '389KTnnlu',
    'name',
    'gives\x20you\x20a\x20friendly\x20reminder\x20if\x20the\x20Clock\x20is\x20not\x20installed\x20and\x20you\x20tick',
    'tick',
    'and',
    'calls',
    'reset',
    'recurring1',
    'delayedFn2',
    'toHaveBeenCalledWith',
    'delayedFunctionScheduler',
    'can\x20be\x20installed\x20for\x20the\x20duration\x20of\x20a\x20passed\x20in\x20function\x20and\x20uninstalled\x20when\x20done',
    'delayedFunctionSchedulerFactory',
    'clearInterval',
    'versions',
    'some',
    'delayedFn',
    'does\x20not\x20install\x20if\x20the\x20current\x20setTimeout\x20is\x20not\x20the\x20original\x20function\x20on\x20the\x20global',
    'Clock\x20(acceptance)',
    'global\x20clearInterval',
    'FakeTimeout',
    'replaces\x20the\x20global\x20timer\x20functions\x20on\x20uninstall',
    'can\x20run\x20setTimeouts/setIntervals\x20synchronously',
    'string',
    'correctly\x20schedules\x20functions\x20while\x20the\x20Clock\x20is\x20advancing',
    'callFake',
    'global\x20setInterval',
    'bar',
    'setTimeout',
    'returns\x20an\x20id\x20for\x20the\x20delayed\x20function',
    '219796KctePb',
    'not',
    'DelayedFunctionScheduler',
    'does\x20not\x20replace\x20clearTimeout\x20until\x20it\x20is\x20installed',
    'clearTimeout',
    'toThrowError',
    '2665XcqTBs',
    'createSpy',
    'constructor',
    'can\x20clear\x20a\x20previously\x20set\x20interval\x20using\x20that\x20interval\x27s\x20handler',
    '797LHAXnN',
    'MockDate'
];
function a26_0x2a67(_0x3ddb8c, _0x4c2aac) {
    return a26_0x2a67 = function (_0x32313c, _0x2a67dd) {
        _0x32313c = _0x32313c - 0x1ac;
        var _0x102ca0 = a26_0x3231[_0x32313c];
        return _0x102ca0;
    }, a26_0x2a67(_0x3ddb8c, _0x4c2aac);
}
var a26_0x472afe = a26_0x2a67;
(function (_0x199254, _0x1584d5) {
    var _0x15913c = a26_0x2a67;
    while (!![]) {
        try {
            var _0x500090 = -parseInt(_0x15913c(0x1e0)) * -parseInt(_0x15913c(0x1bc)) + parseInt(_0x15913c(0x1f8)) + -parseInt(_0x15913c(0x1ac)) + parseInt(_0x15913c(0x1da)) + -parseInt(_0x15913c(0x1ad)) * -parseInt(_0x15913c(0x1b7)) + -parseInt(_0x15913c(0x1e4)) * -parseInt(_0x15913c(0x1eb)) + -parseInt(_0x15913c(0x1b9));
            if (_0x500090 === _0x1584d5)
                break;
            else
                _0x199254['push'](_0x199254['shift']());
        } catch (_0x2c5082) {
            _0x199254['push'](_0x199254['shift']());
        }
    }
}(a26_0x3231, 0x908b9), describe(a26_0x472afe(0x1f6), function () {
    var _0x191a67 = a26_0x472afe, _0x433b78 = typeof process !== 'undefined' && process[_0x191a67(0x1ca)] && typeof process[_0x191a67(0x1ca)]['node'] === _0x191a67(0x1d3);
    it('does\x20not\x20replace\x20setTimeout\x20until\x20it\x20is\x20installed', function () {
        var _0x18a5aa = _0x191a67, _0x8d2a89 = jasmine['createSpy'](_0x18a5aa(0x1b3)), _0x3236b4 = { 'setTimeout': _0x8d2a89 }, _0x27c9d3 = jasmine[_0x18a5aa(0x1b2)](_0x18a5aa(0x1c6), [_0x18a5aa(0x1fa)]), _0x631a6d = jasmine[_0x18a5aa(0x1e1)](_0x18a5aa(0x1cc)), _0x32c959 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x1bdac5 = new jasmineUnderTest[(_0x18a5aa(0x1f6))](_0x3236b4, function () {
                return _0x27c9d3;
            }, _0x32c959);
        _0x3236b4['setTimeout'](_0x631a6d, 0x0), expect(_0x8d2a89)['toHaveBeenCalledWith'](_0x631a6d, 0x0), expect(_0x27c9d3['scheduleFunction'])[_0x18a5aa(0x1db)][_0x18a5aa(0x1f3)](), _0x8d2a89[_0x18a5aa(0x1c1)][_0x18a5aa(0x1c2)](), _0x1bdac5[_0x18a5aa(0x1ba)](), _0x3236b4[_0x18a5aa(0x1d8)](_0x631a6d, 0x0), expect(_0x27c9d3[_0x18a5aa(0x1fa)])[_0x18a5aa(0x1f3)](), expect(_0x8d2a89)[_0x18a5aa(0x1db)][_0x18a5aa(0x1f3)]();
    }), it(_0x191a67(0x1dd), function () {
        var _0x512425 = _0x191a67, _0x25d8be = jasmine[_0x512425(0x1e1)]('global\x20cleartimeout'), _0x2febcd = { 'clearTimeout': _0x25d8be }, _0x1a063b = jasmine[_0x512425(0x1b2)](_0x512425(0x1c6), [_0x512425(0x1ed)]), _0x39a8e3 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x2c7418 = new jasmineUnderTest[(_0x512425(0x1f6))](_0x2febcd, function () {
                return _0x1a063b;
            }, _0x39a8e3);
        _0x2febcd[_0x512425(0x1de)](_0x512425(0x1f5)), expect(_0x25d8be)[_0x512425(0x1c5)](_0x512425(0x1f5)), expect(_0x1a063b[_0x512425(0x1ed)])['not']['toHaveBeenCalled'](), _0x25d8be[_0x512425(0x1c1)][_0x512425(0x1c2)](), _0x2c7418['install'](), _0x2febcd[_0x512425(0x1de)]('foo'), expect(_0x1a063b['removeFunctionWithId'])[_0x512425(0x1f3)](), expect(_0x25d8be)[_0x512425(0x1db)][_0x512425(0x1f3)]();
    }), it('does\x20not\x20replace\x20setInterval\x20until\x20it\x20is\x20installed', function () {
        var _0x1d3904 = _0x191a67, _0x14c30c = jasmine[_0x1d3904(0x1e1)]('global\x20setInterval'), _0x523f7d = { 'setInterval': _0x14c30c }, _0x4288b5 = jasmine[_0x1d3904(0x1b2)](_0x1d3904(0x1c6), [_0x1d3904(0x1fa)]), _0x472c9f = jasmine[_0x1d3904(0x1e1)](_0x1d3904(0x1cc)), _0x2e1017 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x4bdab8 = new jasmineUnderTest['Clock'](_0x523f7d, function () {
                return _0x4288b5;
            }, _0x2e1017);
        _0x523f7d[_0x1d3904(0x1b6)](_0x472c9f, 0x0), expect(_0x14c30c)[_0x1d3904(0x1c5)](_0x472c9f, 0x0), expect(_0x4288b5[_0x1d3904(0x1fa)])[_0x1d3904(0x1db)][_0x1d3904(0x1f3)](), _0x14c30c[_0x1d3904(0x1c1)][_0x1d3904(0x1c2)](), _0x4bdab8[_0x1d3904(0x1ba)](), _0x523f7d['setInterval'](_0x472c9f, 0x0), expect(_0x4288b5[_0x1d3904(0x1fa)])[_0x1d3904(0x1f3)](), expect(_0x14c30c)[_0x1d3904(0x1db)][_0x1d3904(0x1f3)]();
    }), it(_0x191a67(0x1e6), function () {
        var _0x4caa90 = _0x191a67, _0x2491c5 = jasmine[_0x4caa90(0x1e1)]('global\x20clearinterval'), _0x10b088 = { 'clearInterval': _0x2491c5 }, _0x4efb8e = jasmine['createSpyObj'](_0x4caa90(0x1c6), [_0x4caa90(0x1ed)]), _0x2e0beb = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x39c614 = new jasmineUnderTest[(_0x4caa90(0x1f6))](_0x10b088, function () {
                return _0x4efb8e;
            }, _0x2e0beb);
        _0x10b088[_0x4caa90(0x1c9)](_0x4caa90(0x1f5)), expect(_0x2491c5)['toHaveBeenCalledWith'](_0x4caa90(0x1f5)), expect(_0x4efb8e[_0x4caa90(0x1ed)])[_0x4caa90(0x1db)][_0x4caa90(0x1f3)](), _0x2491c5[_0x4caa90(0x1c1)][_0x4caa90(0x1c2)](), _0x39c614['install'](), _0x10b088['clearInterval'](_0x4caa90(0x1f5)), expect(_0x4efb8e[_0x4caa90(0x1ed)])['toHaveBeenCalled'](), expect(_0x2491c5)[_0x4caa90(0x1db)]['toHaveBeenCalled']();
    }), it(_0x191a67(0x1cd), function () {
        var _0xb17a = _0x191a67, _0x344896 = function () {
            }, _0x37492b = function () {
            }, _0x534024 = { 'setTimeout': _0x344896 }, _0x4e6000 = jasmine['createSpy'](_0xb17a(0x1c8)), _0xee1cf8 = {}, _0x2dc696 = new jasmineUnderTest[(_0xb17a(0x1f6))](_0x534024, _0x4e6000, _0xee1cf8);
        _0x534024[_0xb17a(0x1d8)] = _0x37492b, expect(function () {
            var _0xb6d8cf = _0xb17a;
            _0x2dc696[_0xb6d8cf(0x1ba)]();
        })['toThrowError'](/unable to install/), expect(_0x4e6000)[_0xb17a(0x1db)][_0xb17a(0x1f3)](), expect(_0x534024[_0xb17a(0x1d8)])[_0xb17a(0x1bb)](_0x37492b);
    }), it('does\x20not\x20install\x20if\x20the\x20current\x20clearTimeout\x20is\x20not\x20the\x20original\x20function\x20on\x20the\x20global', function () {
        var _0xdbe4d9 = _0x191a67, _0x3400f7 = function () {
            }, _0x3f81cb = function () {
            }, _0x2a0910 = { 'clearTimeout': _0x3400f7 }, _0x390950 = jasmine[_0xdbe4d9(0x1e1)]('delayedFunctionSchedulerFactory'), _0x3fcffb = {}, _0xbde61b = new jasmineUnderTest[(_0xdbe4d9(0x1f6))](_0x2a0910, _0x390950, _0x3fcffb);
        _0x2a0910[_0xdbe4d9(0x1de)] = _0x3f81cb, expect(function () {
            var _0x3a2a32 = _0xdbe4d9;
            _0xbde61b[_0x3a2a32(0x1ba)]();
        })[_0xdbe4d9(0x1df)](/unable to install/), expect(_0x390950)[_0xdbe4d9(0x1db)][_0xdbe4d9(0x1f3)](), expect(_0x2a0910['clearTimeout'])[_0xdbe4d9(0x1bb)](_0x3f81cb);
    }), it('does\x20not\x20install\x20if\x20the\x20current\x20setInterval\x20is\x20not\x20the\x20original\x20function\x20on\x20the\x20global', function () {
        var _0x25acde = _0x191a67, _0x4462c7 = function () {
            }, _0x1f324d = function () {
            }, _0x1944ac = { 'setInterval': _0x4462c7 }, _0x315ca4 = jasmine[_0x25acde(0x1e1)](_0x25acde(0x1c8)), _0x109f65 = {}, _0x148bac = new jasmineUnderTest[(_0x25acde(0x1f6))](_0x1944ac, _0x315ca4, _0x109f65);
        _0x1944ac['setInterval'] = _0x1f324d, expect(function () {
            var _0x474e1e = _0x25acde;
            _0x148bac[_0x474e1e(0x1ba)]();
        })['toThrowError'](/unable to install/), expect(_0x315ca4)[_0x25acde(0x1db)][_0x25acde(0x1f3)](), expect(_0x1944ac[_0x25acde(0x1b6)])[_0x25acde(0x1bb)](_0x1f324d);
    }), it(_0x191a67(0x1b8), function () {
        var _0x5b1ac8 = _0x191a67, _0xbf5fca = function () {
            }, _0xcfbc29 = function () {
            }, _0x507617 = { 'clearInterval': _0xbf5fca }, _0x337137 = jasmine[_0x5b1ac8(0x1e1)](_0x5b1ac8(0x1c8)), _0x27c81f = {}, _0x5a5139 = new jasmineUnderTest['Clock'](_0x507617, _0x337137, _0x27c81f);
        _0x507617['clearInterval'] = _0xcfbc29, expect(function () {
            var _0x4408a3 = _0x5b1ac8;
            _0x5a5139[_0x4408a3(0x1ba)]();
        })[_0x5b1ac8(0x1df)](/unable to install/), expect(_0x337137)[_0x5b1ac8(0x1db)][_0x5b1ac8(0x1f3)](), expect(_0x507617['clearInterval'])['toBe'](_0xcfbc29);
    }), it(_0x191a67(0x1d1), function () {
        var _0x417554 = _0x191a67, _0x3e2ce5 = jasmine[_0x417554(0x1e1)](_0x417554(0x1b3)), _0x423c61 = jasmine['createSpy']('global\x20clearTimeout'), _0x3c919e = jasmine[_0x417554(0x1e1)](_0x417554(0x1d6)), _0x4822c7 = jasmine[_0x417554(0x1e1)](_0x417554(0x1cf)), _0x27259c = {
                'setTimeout': _0x3e2ce5,
                'clearTimeout': _0x423c61,
                'setInterval': _0x3c919e,
                'clearInterval': _0x4822c7
            }, _0x4d2067 = jasmine[_0x417554(0x1b2)]('delayedFunctionScheduler', [
                _0x417554(0x1fa),
                _0x417554(0x1c2)
            ]), _0x137db4 = jasmine[_0x417554(0x1e1)](_0x417554(0x1cc)), _0x4194d2 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x2d04e9 = new jasmineUnderTest[(_0x417554(0x1f6))](_0x27259c, function () {
                return _0x4d2067;
            }, _0x4194d2);
        _0x2d04e9[_0x417554(0x1ba)](), _0x2d04e9[_0x417554(0x1e9)](), _0x27259c[_0x417554(0x1d8)](_0x137db4, 0x0), _0x27259c[_0x417554(0x1de)]('foo'), _0x27259c[_0x417554(0x1b6)](_0x137db4, 0xa), _0x27259c[_0x417554(0x1c9)](_0x417554(0x1d7)), expect(_0x3e2ce5)[_0x417554(0x1c5)](_0x137db4, 0x0), expect(_0x423c61)['toHaveBeenCalledWith'](_0x417554(0x1f5)), expect(_0x3c919e)['toHaveBeenCalledWith'](_0x137db4, 0xa), expect(_0x4822c7)[_0x417554(0x1c5)](_0x417554(0x1d7)), expect(_0x4d2067[_0x417554(0x1fa)])['not'][_0x417554(0x1f3)]();
    }), it(_0x191a67(0x1c7), function () {
        var _0x126c33 = _0x191a67, _0x2fbd41 = jasmine[_0x126c33(0x1e1)](_0x126c33(0x1b3)), _0x1363f9 = jasmine[_0x126c33(0x1e1)](_0x126c33(0x1b0)), _0x4e30ce = jasmine[_0x126c33(0x1e1)](_0x126c33(0x1d6)), _0x1c20c7 = jasmine[_0x126c33(0x1e1)](_0x126c33(0x1cf)), _0x5632c6 = {
                'setTimeout': _0x2fbd41,
                'clearTimeout': _0x1363f9,
                'setInterval': _0x4e30ce,
                'clearInterval': _0x1c20c7
            }, _0x446494 = jasmine['createSpyObj'](_0x126c33(0x1c6), [
                _0x126c33(0x1fa),
                _0x126c33(0x1c2),
                _0x126c33(0x1ed)
            ]), _0x47947d = jasmine[_0x126c33(0x1e1)]('delayedFn'), _0x512f59 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x298711 = new jasmineUnderTest['Clock'](_0x5632c6, function () {
                return _0x446494;
            }, _0x512f59), _0x2275cf = ![];
        _0x298711[_0x126c33(0x1f0)](function () {
            var _0x5dae95 = _0x126c33;
            _0x5632c6[_0x5dae95(0x1d8)](_0x47947d, 0x0), _0x5632c6[_0x5dae95(0x1de)](_0x5dae95(0x1f5)), _0x5632c6['setInterval'](_0x47947d, 0xa), _0x5632c6[_0x5dae95(0x1c9)](_0x5dae95(0x1d7)), _0x2275cf = !![];
        }), expect(_0x2275cf)['toBe'](!![]), expect(_0x2fbd41)[_0x126c33(0x1db)]['toHaveBeenCalled'](), expect(_0x1363f9)[_0x126c33(0x1db)][_0x126c33(0x1f3)](), expect(_0x4e30ce)[_0x126c33(0x1db)][_0x126c33(0x1f3)](), expect(_0x1c20c7)[_0x126c33(0x1db)][_0x126c33(0x1f3)](), expect(_0x446494[_0x126c33(0x1fa)])[_0x126c33(0x1f3)](), _0x446494[_0x126c33(0x1fa)][_0x126c33(0x1c1)][_0x126c33(0x1c2)](), _0x5632c6[_0x126c33(0x1d8)](_0x47947d, 0x0), _0x5632c6[_0x126c33(0x1de)](_0x126c33(0x1f5)), _0x5632c6[_0x126c33(0x1b6)](_0x47947d, 0xa), _0x5632c6['clearInterval']('bar'), expect(_0x2fbd41)[_0x126c33(0x1c5)](_0x47947d, 0x0), expect(_0x1363f9)[_0x126c33(0x1c5)](_0x126c33(0x1f5)), expect(_0x4e30ce)[_0x126c33(0x1c5)](_0x47947d, 0xa), expect(_0x1c20c7)[_0x126c33(0x1c5)](_0x126c33(0x1d7)), expect(_0x446494[_0x126c33(0x1fa)])[_0x126c33(0x1db)][_0x126c33(0x1f3)]();
    }), it('can\x20be\x20installed\x20for\x20the\x20duration\x20of\x20a\x20passed\x20in\x20function\x20and\x20uninstalled\x20if\x20an\x20error\x20is\x20thrown', function () {
        var _0x4913cf = _0x191a67, _0x27a387 = jasmine[_0x4913cf(0x1e1)]('global\x20setTimeout'), _0x2f3b29 = jasmine[_0x4913cf(0x1e1)](_0x4913cf(0x1b0)), _0x61699d = jasmine[_0x4913cf(0x1e1)](_0x4913cf(0x1d6)), _0x47da7b = jasmine[_0x4913cf(0x1e1)](_0x4913cf(0x1cf)), _0x55d075 = {
                'setTimeout': _0x27a387,
                'clearTimeout': _0x2f3b29,
                'setInterval': _0x61699d,
                'clearInterval': _0x47da7b
            }, _0x13a1fe = jasmine[_0x4913cf(0x1b2)](_0x4913cf(0x1c6), [
                _0x4913cf(0x1fa),
                _0x4913cf(0x1c2),
                _0x4913cf(0x1ed)
            ]), _0x50d48f = jasmine['createSpy']('delayedFn'), _0x2a338a = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0xd3afbf = new jasmineUnderTest[(_0x4913cf(0x1f6))](_0x55d075, function () {
                return _0x13a1fe;
            }, _0x2a338a), _0x35d3e9 = ![];
        expect(function () {
            var _0x228f06 = _0x4913cf;
            _0xd3afbf[_0x228f06(0x1f0)](function () {
                var _0x6b3f22 = _0x228f06;
                _0x55d075['setTimeout'](_0x50d48f, 0x0), _0x55d075[_0x6b3f22(0x1de)](_0x6b3f22(0x1f5)), _0x55d075[_0x6b3f22(0x1b6)](_0x50d48f, 0xa), _0x55d075[_0x6b3f22(0x1c9)](_0x6b3f22(0x1d7)), _0x35d3e9 = !![];
                throw _0x6b3f22(0x1b5);
            });
        })[_0x4913cf(0x1f1)](_0x4913cf(0x1b5)), expect(_0x35d3e9)[_0x4913cf(0x1bb)](!![]), expect(_0x27a387)['not'][_0x4913cf(0x1f3)](), expect(_0x2f3b29)[_0x4913cf(0x1db)]['toHaveBeenCalled'](), expect(_0x61699d)[_0x4913cf(0x1db)][_0x4913cf(0x1f3)](), expect(_0x47da7b)[_0x4913cf(0x1db)]['toHaveBeenCalled'](), expect(_0x13a1fe[_0x4913cf(0x1fa)])[_0x4913cf(0x1f3)](), _0x13a1fe['scheduleFunction'][_0x4913cf(0x1c1)][_0x4913cf(0x1c2)](), _0x55d075[_0x4913cf(0x1d8)](_0x50d48f, 0x0), _0x55d075[_0x4913cf(0x1de)]('foo'), _0x55d075['setInterval'](_0x50d48f, 0xa), _0x55d075['clearInterval'](_0x4913cf(0x1d7)), expect(_0x27a387)[_0x4913cf(0x1c5)](_0x50d48f, 0x0), expect(_0x2f3b29)[_0x4913cf(0x1c5)](_0x4913cf(0x1f5)), expect(_0x61699d)['toHaveBeenCalledWith'](_0x50d48f, 0xa), expect(_0x47da7b)[_0x4913cf(0x1c5)]('bar'), expect(_0x13a1fe['scheduleFunction'])[_0x4913cf(0x1db)]['toHaveBeenCalled']();
    }), it(_0x191a67(0x1af), function () {
        var _0x42241d = _0x191a67, _0xcc7c92 = jasmine[_0x42241d(0x1e1)](_0x42241d(0x1d8)), _0x464c30 = jasmine[_0x42241d(0x1e1)](_0x42241d(0x1fa)), _0x188c52 = { 'scheduleFunction': _0x464c30 }, _0x1f7447 = { 'setTimeout': _0xcc7c92 }, _0x396dd1 = jasmine['createSpy'](_0x42241d(0x1cc)), _0x27e105 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x3cde53 = new jasmineUnderTest[(_0x42241d(0x1f6))](_0x1f7447, function () {
                return _0x188c52;
            }, _0x27e105), _0x32da73 = new _0x3cde53[(_0x42241d(0x1d0))]();
        _0x3cde53['install'](), _0x3cde53[_0x42241d(0x1d8)](_0x396dd1, 0x0, 'a', 'b'), expect(_0xcc7c92)['not'][_0x42241d(0x1f3)](), !_0x433b78 ? expect(_0x188c52[_0x42241d(0x1fa)])[_0x42241d(0x1c5)](_0x396dd1, 0x0, [
            'a',
            'b'
        ]) : expect(_0x188c52['scheduleFunction'])[_0x42241d(0x1c5)](_0x396dd1, 0x0, [
            'a',
            'b'
        ], ![], _0x32da73);
    }), it(_0x191a67(0x1d9), function () {
        var _0x3ecf8a = _0x191a67, _0x356b64 = jasmine[_0x3ecf8a(0x1e1)](_0x3ecf8a(0x1d8)), _0x364b27 = 0x7b, _0x439fa0 = jasmine['createSpy'](_0x3ecf8a(0x1fa))[_0x3ecf8a(0x1c0)]['returnValue'](_0x364b27), _0x488336 = { 'scheduleFunction': _0x439fa0 }, _0x3052cc = { 'setTimeout': _0x356b64 }, _0x8a121 = jasmine[_0x3ecf8a(0x1e1)](_0x3ecf8a(0x1cc)), _0x424a50 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x1fcbf4 = new jasmineUnderTest['Clock'](_0x3052cc, function () {
                return _0x488336;
            }, _0x424a50), _0x153b8a;
        _0x1fcbf4['install'](), _0x153b8a = _0x1fcbf4['setTimeout'](_0x8a121, 0x0), !_0x433b78 ? expect(_0x153b8a)['toEqual'](0x7b) : expect(_0x153b8a[_0x3ecf8a(0x1e2)][_0x3ecf8a(0x1bd)])['toEqual'](_0x3ecf8a(0x1d0));
    }), it('clears\x20the\x20scheduled\x20function\x20with\x20the\x20scheduler', function () {
        var _0x3d35f6 = _0x191a67, _0x2e6297 = jasmine[_0x3d35f6(0x1e1)](_0x3d35f6(0x1de)), _0x505b09 = jasmine['createSpyObj']('delayedFunctionScheduler', [_0x3d35f6(0x1ed)]), _0x4f5bc7 = { 'setTimeout': _0x2e6297 }, _0x1752b6 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x531dde = new jasmineUnderTest[(_0x3d35f6(0x1f6))](_0x4f5bc7, function () {
                return _0x505b09;
            }, _0x1752b6);
        _0x531dde[_0x3d35f6(0x1ba)](), _0x531dde[_0x3d35f6(0x1de)](0x7b), expect(_0x2e6297)[_0x3d35f6(0x1db)][_0x3d35f6(0x1f3)](), expect(_0x505b09[_0x3d35f6(0x1ed)])[_0x3d35f6(0x1c5)](0x7b);
    }), it('schedules\x20the\x20delayed\x20function\x20with\x20the\x20fake\x20timer', function () {
        var _0x50d3f9 = _0x191a67, _0x3b0151 = jasmine['createSpy'](_0x50d3f9(0x1b6)), _0x3f5c6a = jasmine['createSpy'](_0x50d3f9(0x1fa)), _0x2ee865 = { 'scheduleFunction': _0x3f5c6a }, _0x57301a = { 'setInterval': _0x3b0151 }, _0x14055b = jasmine[_0x50d3f9(0x1e1)](_0x50d3f9(0x1cc)), _0x5305e4 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x47b378 = new jasmineUnderTest[(_0x50d3f9(0x1f6))](_0x57301a, function () {
                return _0x2ee865;
            }, _0x5305e4), _0x3c0589 = new _0x47b378[(_0x50d3f9(0x1d0))]();
        _0x47b378[_0x50d3f9(0x1ba)](), _0x47b378[_0x50d3f9(0x1b6)](_0x14055b, 0x0, 'a', 'b'), expect(_0x3b0151)[_0x50d3f9(0x1db)][_0x50d3f9(0x1f3)](), !_0x433b78 ? expect(_0x2ee865[_0x50d3f9(0x1fa)])[_0x50d3f9(0x1c5)](_0x14055b, 0x0, [
            'a',
            'b'
        ], !![]) : expect(_0x2ee865['scheduleFunction'])[_0x50d3f9(0x1c5)](_0x14055b, 0x0, [
            'a',
            'b'
        ], !![], _0x3c0589);
    }), it('returns\x20an\x20id\x20for\x20the\x20delayed\x20function', function () {
        var _0x3ab11d = _0x191a67, _0x1030f0 = jasmine[_0x3ab11d(0x1e1)](_0x3ab11d(0x1b6)), _0x203d77 = 0x7b, _0x445ab5 = jasmine[_0x3ab11d(0x1e1)]('scheduleFunction')[_0x3ab11d(0x1c0)]['returnValue'](_0x203d77), _0x4f4ffc = { 'scheduleFunction': _0x445ab5 }, _0x595d45 = { 'setInterval': _0x1030f0 }, _0x21e5be = jasmine['createSpy'](_0x3ab11d(0x1cc)), _0x46a012 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x3cbdf0 = new jasmineUnderTest[(_0x3ab11d(0x1f6))](_0x595d45, function () {
                return _0x4f4ffc;
            }, _0x46a012), _0x11ff2e;
        _0x3cbdf0[_0x3ab11d(0x1ba)](), _0x11ff2e = _0x3cbdf0[_0x3ab11d(0x1b6)](_0x21e5be, 0x0), !_0x433b78 ? expect(_0x11ff2e)[_0x3ab11d(0x1f2)](0x7b) : expect(_0x11ff2e[_0x3ab11d(0x1e2)][_0x3ab11d(0x1bd)])[_0x3ab11d(0x1f2)](_0x3ab11d(0x1d0));
    }), it(_0x191a67(0x1ec), function () {
        var _0x2ea6f9 = _0x191a67, _0x4794f1 = jasmine[_0x2ea6f9(0x1e1)](_0x2ea6f9(0x1c9)), _0xeed90b = jasmine[_0x2ea6f9(0x1b2)](_0x2ea6f9(0x1c6), [_0x2ea6f9(0x1ed)]), _0x460ec0 = { 'setInterval': _0x4794f1 }, _0x5bd411 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x2f459f = new jasmineUnderTest['Clock'](_0x460ec0, function () {
                return _0xeed90b;
            }, _0x5bd411);
        _0x2f459f[_0x2ea6f9(0x1ba)](), _0x2f459f[_0x2ea6f9(0x1c9)](0x7b), expect(_0x4794f1)[_0x2ea6f9(0x1db)]['toHaveBeenCalled'](), expect(_0xeed90b[_0x2ea6f9(0x1ed)])[_0x2ea6f9(0x1c5)](0x7b);
    }), it(_0x191a67(0x1be), function () {
        var _0x55c711 = _0x191a67, _0xb80039 = new jasmineUnderTest[(_0x55c711(0x1f6))]({}, jasmine['createSpyObj'](_0x55c711(0x1c6), ['tick']));
        expect(function () {
            var _0x2f13a7 = _0x55c711;
            _0xb80039[_0x2f13a7(0x1bf)](0x32);
        })[_0x55c711(0x1f1)]();
    });
}), describe(a26_0x472afe(0x1ce), function () {
    var _0xc405a4 = a26_0x472afe;
    it(_0xc405a4(0x1d2), function () {
        var _0x205048 = _0xc405a4, _0x57ac31 = jasmine[_0x205048(0x1e1)](_0x205048(0x1b4)), _0x27b4e5 = jasmine[_0x205048(0x1e1)](_0x205048(0x1c4)), _0x848dc6 = jasmine[_0x205048(0x1e1)](_0x205048(0x1b1)), _0x5a35a8 = jasmine[_0x205048(0x1e1)](_0x205048(0x1c3)), _0x219c69 = new jasmineUnderTest[(_0x205048(0x1dc))](), _0x1eada9 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x428ad0 = new jasmineUnderTest[(_0x205048(0x1f6))]({ 'setTimeout': setTimeout }, function () {
                return _0x219c69;
            }, _0x1eada9);
        _0x428ad0['install'](), _0x428ad0[_0x205048(0x1d8)](_0x57ac31, 0x0);
        var _0x40e69b = _0x428ad0['setInterval'](_0x5a35a8, 0x32);
        _0x428ad0[_0x205048(0x1d8)](_0x27b4e5, 0x64), _0x428ad0[_0x205048(0x1d8)](_0x848dc6, 0xc8), expect(_0x57ac31)['not'][_0x205048(0x1f3)](), expect(_0x27b4e5)['not'][_0x205048(0x1f3)](), expect(_0x848dc6)[_0x205048(0x1db)][_0x205048(0x1f3)](), _0x428ad0[_0x205048(0x1bf)](0x0), expect(_0x57ac31)[_0x205048(0x1f3)](), expect(_0x27b4e5)[_0x205048(0x1db)][_0x205048(0x1f3)](), expect(_0x848dc6)[_0x205048(0x1db)][_0x205048(0x1f3)](), _0x428ad0['tick'](0x32), expect(_0x5a35a8)[_0x205048(0x1f3)](), expect(_0x5a35a8[_0x205048(0x1c1)][_0x205048(0x1ea)]())[_0x205048(0x1bb)](0x1), expect(_0x27b4e5)[_0x205048(0x1db)][_0x205048(0x1f3)](), expect(_0x848dc6)[_0x205048(0x1db)]['toHaveBeenCalled'](), _0x428ad0[_0x205048(0x1bf)](0x32), expect(_0x5a35a8[_0x205048(0x1c1)][_0x205048(0x1ea)]())[_0x205048(0x1bb)](0x2), expect(_0x27b4e5)[_0x205048(0x1f3)](), expect(_0x848dc6)['not'][_0x205048(0x1f3)](), _0x428ad0[_0x205048(0x1bf)](0x64), expect(_0x5a35a8[_0x205048(0x1c1)]['count']())[_0x205048(0x1bb)](0x4), expect(_0x848dc6)[_0x205048(0x1f3)](), _0x428ad0['clearInterval'](_0x40e69b), _0x428ad0[_0x205048(0x1bf)](0x32), expect(_0x5a35a8['calls'][_0x205048(0x1ea)]())[_0x205048(0x1bb)](0x4);
    }), it('can\x20clear\x20a\x20previously\x20set\x20timeout', function () {
        var _0x5bdf32 = _0xc405a4, _0x16ca82 = jasmine[_0x5bdf32(0x1e1)]('clearedFn'), _0x5e8430 = new jasmineUnderTest['DelayedFunctionScheduler'](), _0x3d820a = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x19d7ca = new jasmineUnderTest[(_0x5bdf32(0x1f6))]({
                'setTimeout': function () {
                }
            }, function () {
                return _0x5e8430;
            }, _0x3d820a), _0x2eeb12;
        _0x19d7ca[_0x5bdf32(0x1ba)](), _0x2eeb12 = _0x19d7ca[_0x5bdf32(0x1d8)](_0x16ca82, 0x64), expect(_0x16ca82)[_0x5bdf32(0x1db)][_0x5bdf32(0x1f3)](), _0x19d7ca[_0x5bdf32(0x1de)](_0x2eeb12), _0x19d7ca[_0x5bdf32(0x1bf)](0x64), expect(_0x16ca82)[_0x5bdf32(0x1db)][_0x5bdf32(0x1f3)]();
    }), it(_0xc405a4(0x1e3), function () {
        var _0x2da57c = _0xc405a4, _0x2795dc = jasmine[_0x2da57c(0x1e1)](_0x2da57c(0x1f7)), _0x2ad1d1 = new jasmineUnderTest[(_0x2da57c(0x1dc))](), _0x2e3f87 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x5a3da8 = new jasmineUnderTest[(_0x2da57c(0x1f6))]({
                'setInterval': function () {
                }
            }, function () {
                return _0x2ad1d1;
            }, _0x2e3f87), _0x37bc06;
        _0x5a3da8[_0x2da57c(0x1ba)](), _0x37bc06 = _0x5a3da8[_0x2da57c(0x1b6)](function () {
            var _0xfaec8e = _0x2da57c;
            _0x2795dc(), _0x5a3da8[_0xfaec8e(0x1c9)](_0x37bc06);
        }, 0x64), _0x5a3da8[_0x2da57c(0x1bf)](0xc8), expect(_0x2795dc[_0x2da57c(0x1c1)][_0x2da57c(0x1ea)]())[_0x2da57c(0x1f2)](0x1);
    }), it('correctly\x20schedules\x20functions\x20after\x20the\x20Clock\x20has\x20advanced', function () {
        var _0x6fe3e1 = _0xc405a4, _0x10a647 = jasmine[_0x6fe3e1(0x1e1)](_0x6fe3e1(0x1b4)), _0x30871d = new jasmineUnderTest[(_0x6fe3e1(0x1dc))](), _0x39765b = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x2ed223 = new jasmineUnderTest['Clock']({
                'setTimeout': function () {
                }
            }, function () {
                return _0x30871d;
            }, _0x39765b);
        _0x2ed223[_0x6fe3e1(0x1ba)](), _0x2ed223['tick'](0x64), _0x2ed223[_0x6fe3e1(0x1d8)](_0x10a647, 0xa, [
            _0x6fe3e1(0x1cb),
            'arg'
        ]), _0x2ed223[_0x6fe3e1(0x1bf)](0x5), expect(_0x10a647)[_0x6fe3e1(0x1db)][_0x6fe3e1(0x1f3)](), _0x2ed223[_0x6fe3e1(0x1bf)](0x5), expect(_0x10a647)[_0x6fe3e1(0x1f3)]();
    }), it(_0xc405a4(0x1d4), function () {
        var _0x459c55 = _0xc405a4, _0x354f2f = jasmine[_0x459c55(0x1e1)](_0x459c55(0x1b4)), _0x5a5824 = jasmine['createSpy'](_0x459c55(0x1c4)), _0x57b503 = new jasmineUnderTest[(_0x459c55(0x1dc))](), _0x5bac44 = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x1b5c35 = new jasmineUnderTest[(_0x459c55(0x1f6))]({
                'setTimeout': function () {
                }
            }, function () {
                return _0x57b503;
            }, _0x5bac44);
        _0x354f2f['and'][_0x459c55(0x1d5)](function () {
            var _0x117cf8 = _0x459c55;
            _0x1b5c35[_0x117cf8(0x1d8)](_0x5a5824, 0x0);
        }), _0x1b5c35[_0x459c55(0x1ba)](), _0x1b5c35['setTimeout'](_0x354f2f, 0x5), _0x1b5c35[_0x459c55(0x1bf)](0x5), expect(_0x354f2f)[_0x459c55(0x1f3)](), expect(_0x5a5824)[_0x459c55(0x1db)][_0x459c55(0x1f3)](), _0x1b5c35[_0x459c55(0x1bf)](), expect(_0x5a5824)[_0x459c55(0x1f3)]();
    }), it('correctly\x20calls\x20functions\x20scheduled\x20while\x20the\x20Clock\x20is\x20advancing', function () {
        var _0xcc62c9 = _0xc405a4, _0x18aeec = jasmine['createSpy'](_0xcc62c9(0x1b4)), _0xf99aec = jasmine[_0xcc62c9(0x1e1)](_0xcc62c9(0x1c4)), _0x7b8b8 = new jasmineUnderTest[(_0xcc62c9(0x1dc))](), _0x1759fe = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x4b17fd = new jasmineUnderTest[(_0xcc62c9(0x1f6))]({
                'setTimeout': function () {
                }
            }, function () {
                return _0x7b8b8;
            }, _0x1759fe);
        _0x18aeec[_0xcc62c9(0x1c0)][_0xcc62c9(0x1d5)](function () {
            var _0x5c3508 = _0xcc62c9;
            _0x4b17fd[_0x5c3508(0x1d8)](_0xf99aec, 0x1);
        }), _0x4b17fd[_0xcc62c9(0x1ba)](), _0x4b17fd['setTimeout'](_0x18aeec, 0x5), _0x4b17fd['tick'](0x6), expect(_0x18aeec)[_0xcc62c9(0x1f3)](), expect(_0xf99aec)[_0xcc62c9(0x1f3)]();
    }), it(_0xc405a4(0x1e8), function () {
        var _0x542cbf = _0xc405a4, _0x54badc = jasmine[_0x542cbf(0x1e1)](_0x542cbf(0x1b4)), _0x153eb5 = jasmine[_0x542cbf(0x1e1)](_0x542cbf(0x1c4)), _0x31b38e = new jasmineUnderTest['DelayedFunctionScheduler'](), _0x11356e = {
                'install': function () {
                },
                'tick': function () {
                },
                'uninstall': function () {
                }
            }, _0x2a52cd = new jasmineUnderTest['Clock']({
                'setTimeout': function () {
                }
            }, function () {
                return _0x31b38e;
            }, _0x11356e);
        _0x54badc[_0x542cbf(0x1c0)][_0x542cbf(0x1d5)](function () {
            var _0x3e9ef8 = _0x542cbf;
            _0x2a52cd[_0x3e9ef8(0x1e9)](), _0x2a52cd[_0x3e9ef8(0x1ba)](), _0x2a52cd[_0x3e9ef8(0x1d8)](_0x153eb5, 0x0);
        }), _0x2a52cd[_0x542cbf(0x1ba)](), _0x2a52cd[_0x542cbf(0x1d8)](_0x54badc, 0x1), _0x2a52cd[_0x542cbf(0x1bf)](0x1), expect(_0x54badc)[_0x542cbf(0x1f3)](), expect(_0x153eb5)[_0x542cbf(0x1db)][_0x542cbf(0x1f3)](), _0x2a52cd[_0x542cbf(0x1bf)](0x1), expect(_0x153eb5)[_0x542cbf(0x1f3)]();
    }), it(_0xc405a4(0x1f9), function () {
        var _0x38a8ed = _0xc405a4, _0x33c681 = new jasmineUnderTest[(_0x38a8ed(0x1dc))](), _0x16f78e = { 'Date': Date }, _0x1b0401 = new jasmineUnderTest['MockDate'](_0x16f78e), _0x3a74f0 = new jasmineUnderTest[(_0x38a8ed(0x1f6))]({ 'setTimeout': setTimeout }, function () {
                return _0x33c681;
            }, _0x1b0401);
        _0x3a74f0[_0x38a8ed(0x1ba)](), expect(_0x16f78e[_0x38a8ed(0x1e7)])[_0x38a8ed(0x1f2)](Date);
        var _0x23af6f = new _0x16f78e[(_0x38a8ed(0x1e7))]()[_0x38a8ed(0x1ae)]();
        _0x3a74f0[_0x38a8ed(0x1bf)](0x32), expect(new _0x16f78e[(_0x38a8ed(0x1e7))]()[_0x38a8ed(0x1ae)]() - _0x23af6f)[_0x38a8ed(0x1db)][_0x38a8ed(0x1f2)](0x32);
    }), it(_0xc405a4(0x1ee), function () {
        var _0x3622cd = _0xc405a4, _0x287db6 = new jasmineUnderTest[(_0x3622cd(0x1dc))](), _0x1647fa = { 'Date': Date }, _0x2944a2 = new jasmineUnderTest[(_0x3622cd(0x1e5))](_0x1647fa), _0x326b8d = new jasmineUnderTest[(_0x3622cd(0x1f6))]({ 'setTimeout': setTimeout }, function () {
                return _0x287db6;
            }, _0x2944a2);
        _0x326b8d[_0x3622cd(0x1ba)]()[_0x3622cd(0x1f4)]();
        var _0xdaf022 = new _0x1647fa[(_0x3622cd(0x1e7))]()['getTime']();
        _0x326b8d[_0x3622cd(0x1bf)](0x32), expect(new _0x1647fa['Date']()['getTime']() - _0xdaf022)[_0x3622cd(0x1f2)](0x32);
        var _0x5496cd = 0x0;
        _0x326b8d[_0x3622cd(0x1d8)](function () {
            var _0x55605b = _0x3622cd;
            _0x5496cd = new _0x1647fa['Date']()[_0x55605b(0x1ae)]();
        }, 0x64), _0x326b8d['tick'](0x64), expect(_0x5496cd - _0xdaf022)[_0x3622cd(0x1f2)](0x96);
    }), it('mocks\x20the\x20Date\x20object\x20and\x20sets\x20it\x20to\x20a\x20given\x20time', function () {
        var _0x374637 = _0xc405a4, _0x20b371 = new jasmineUnderTest[(_0x374637(0x1dc))](), _0x3e9b4f = { 'Date': Date }, _0x33a077 = new jasmineUnderTest[(_0x374637(0x1e5))](_0x3e9b4f), _0x34ae59 = new jasmineUnderTest[(_0x374637(0x1f6))]({ 'setTimeout': setTimeout }, function () {
                return _0x20b371;
            }, _0x33a077), _0x5b6457 = new Date(0x7dd, 0x9, 0x17);
        _0x34ae59[_0x374637(0x1ba)]()[_0x374637(0x1f4)](_0x5b6457);
        var _0x1aa297 = new _0x3e9b4f[(_0x374637(0x1e7))]()[_0x374637(0x1ae)]();
        expect(_0x1aa297)[_0x374637(0x1f2)](_0x5b6457[_0x374637(0x1ae)]()), _0x34ae59[_0x374637(0x1bf)](0x32), expect(new _0x3e9b4f[(_0x374637(0x1e7))]()[_0x374637(0x1ae)]())[_0x374637(0x1f2)](_0x5b6457[_0x374637(0x1ae)]() + 0x32);
        var _0x237865 = 0x0;
        _0x34ae59[_0x374637(0x1d8)](function () {
            _0x237865 = new _0x3e9b4f['Date']()['getTime']();
        }, 0x64), _0x34ae59['tick'](0x64), expect(_0x237865)[_0x374637(0x1f2)](_0x5b6457['getTime']() + 0x96);
    }), it(_0xc405a4(0x1ef), function () {
        var _0x25f81e = _0xc405a4, _0x2feff3 = new jasmineUnderTest[(_0x25f81e(0x1dc))](), _0x5d7359 = { 'Date': Date }, _0x1bf2ef = new jasmineUnderTest[(_0x25f81e(0x1e5))](_0x5d7359), _0x53f6fb = new jasmineUnderTest[(_0x25f81e(0x1f6))]({ 'setTimeout': setTimeout }, function () {
                return _0x2feff3;
            }, _0x1bf2ef), _0x4db4d1 = new Date();
        _0x53f6fb[_0x25f81e(0x1ba)]()[_0x25f81e(0x1f4)](_0x4db4d1);
        var _0x48b2c3 = [], _0x58a15b = function () {
                _0x48b2c3['push'](_0x5d7359['Date']()['getTime']());
            };
        _0x2feff3[_0x25f81e(0x1fa)](_0x58a15b), _0x2feff3[_0x25f81e(0x1fa)](_0x58a15b, 0x1), _0x2feff3['scheduleFunction'](_0x58a15b, 0x3), _0x53f6fb[_0x25f81e(0x1bf)](0x1), expect(_0x5d7359[_0x25f81e(0x1e7)]()['getTime']())[_0x25f81e(0x1f2)](_0x4db4d1[_0x25f81e(0x1ae)]() + 0x1), _0x53f6fb[_0x25f81e(0x1bf)](0x3), expect(_0x5d7359[_0x25f81e(0x1e7)]()[_0x25f81e(0x1ae)]())['toEqual'](_0x4db4d1[_0x25f81e(0x1ae)]() + 0x4), _0x53f6fb[_0x25f81e(0x1bf)](0x1), expect(_0x5d7359[_0x25f81e(0x1e7)]()[_0x25f81e(0x1ae)]())[_0x25f81e(0x1f2)](_0x4db4d1['getTime']() + 0x5), expect(_0x48b2c3)[_0x25f81e(0x1f2)]([
            _0x4db4d1[_0x25f81e(0x1ae)](),
            _0x4db4d1[_0x25f81e(0x1ae)]() + 0x1,
            _0x4db4d1[_0x25f81e(0x1ae)]() + 0x3
        ]);
    }), it('correctly\x20clears\x20a\x20scheduled\x20timeout\x20while\x20the\x20Clock\x20is\x20advancing', function () {
        var _0x4f6a91 = _0xc405a4, _0x4c86b6 = new jasmineUnderTest['DelayedFunctionScheduler'](), _0x329f69 = {
                'Date': Date,
                'setTimeout': undefined
            }, _0x5d461d = new jasmineUnderTest[(_0x4f6a91(0x1e5))](_0x329f69), _0x478176 = new jasmineUnderTest[(_0x4f6a91(0x1f6))](_0x329f69, function () {
                return _0x4c86b6;
            }, _0x5d461d);
        _0x478176[_0x4f6a91(0x1ba)]();
        var _0x4b181a;
        _0x329f69[_0x4f6a91(0x1d8)](function () {
            var _0x11791e = _0x4f6a91;
            _0x329f69[_0x11791e(0x1de)](_0x4b181a);
        }, 0x64), _0x4b181a = _0x329f69[_0x4f6a91(0x1d8)](fail, 0x64), _0x478176['tick'](0x64);
    }), it('correctly\x20clears\x20a\x20scheduled\x20interval\x20while\x20the\x20Clock\x20is\x20advancing', function () {
        var _0xc10b7c = _0xc405a4, _0x21b3c8 = new jasmineUnderTest[(_0xc10b7c(0x1dc))](), _0x10cd03 = {
                'Date': Date,
                'setTimeout': undefined
            }, _0x121e00 = new jasmineUnderTest[(_0xc10b7c(0x1e5))](_0x10cd03), _0x1d903c = new jasmineUnderTest[(_0xc10b7c(0x1f6))](_0x10cd03, function () {
                return _0x21b3c8;
            }, _0x121e00);
        _0x1d903c[_0xc10b7c(0x1ba)]();
        var _0x5814da;
        _0x10cd03[_0xc10b7c(0x1b6)](function () {
            var _0x392082 = _0xc10b7c;
            _0x10cd03[_0x392082(0x1c9)](_0x5814da);
        }, 0x64), _0x5814da = _0x10cd03['setInterval'](fail, 0x64), _0x1d903c[_0xc10b7c(0x1bf)](0x190);
    });
}));