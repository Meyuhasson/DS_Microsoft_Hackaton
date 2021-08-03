var a49_0x3190 = [
    'toBe',
    '910236dyzfea',
    '1480847dELiyk',
    '7nUEbow',
    'should\x20return\x20false\x20if\x20the\x20argument\x20is\x20not\x20an\x20array',
    'isPromiseLike',
    '3YgloHd',
    'should\x20return\x20false\x20for\x20promise\x20like\x20objects',
    'promise\x20utils',
    'given\x20two\x20objects\x20A\x20and\x20B,\x20returns\x20the\x20properties\x20in\x20A\x20not\x20present\x20in\x20B',
    '117143snSJdv',
    '3IlqUrR',
    'get\x20property\x20descriptor\x20from\x20object\x20property',
    '1CeksLQ',
    'isPromise',
    'should\x20return\x20false\x20for\x20strings',
    'objectDifference',
    '6893Vdlbey',
    '233gyXtgV',
    'should\x20return\x20\x20true\x20for\x20promise\x20like\x20objects',
    'should\x20return\x20false\x20for\x20arrays',
    'isArray_',
    'prop',
    'toMatch',
    'should\x20return\x20false\x20for\x20numbers',
    'isUndefined',
    'should\x20return\x20true\x20if\x20the\x20argument\x20is\x20an\x20array',
    'isObject_',
    'should\x20return\x20false\x20for\x20boolean\x20values',
    '69541idPuVr',
    '2896UDnApt',
    'returns\x20the\x20file\x20containing\x20jasmine.util',
    'get\x20property\x20descriptor\x20from\x20object',
    '547NmxnAW',
    'should\x20return\x20false\x20for\x20objects',
    'should\x20return\x20false\x20if\x20the\x20argument\x20is\x20not\x20an\x20object',
    'should\x20return\x20false\x20for\x20undefined',
    'toEqual',
    'diz\x20be\x20undefined\x20yo',
    'util',
    'should\x20return\x20true\x20when\x20passed\x20a\x20native\x20promise',
    'only\x20looks\x20at\x20own\x20properties\x20of\x20both\x20objects',
    'foo',
    '1330029zLBCZk',
    'jasmineFile',
    'getOwnPropertyDescriptor',
    'prototype',
    'Not\x20a\x20function\x20:O',
    'should\x20return\x20true\x20if\x20the\x20argument\x20is\x20an\x20object',
    'hello',
    'getPropertyDescriptor'
];
function a49_0x4d2f(_0x2893a3, _0x178d18) {
    return a49_0x4d2f = function (_0x3190fa, _0x4d2fa2) {
        _0x3190fa = _0x3190fa - 0x64;
        var _0x440c4b = a49_0x3190[_0x3190fa];
        return _0x440c4b;
    }, a49_0x4d2f(_0x2893a3, _0x178d18);
}
(function (_0x409905, _0x4878c3) {
    var _0x51752f = a49_0x4d2f;
    while (!![]) {
        try {
            var _0x161ba0 = parseInt(_0x51752f(0x65)) * parseInt(_0x51752f(0x8d)) + parseInt(_0x51752f(0x75)) * parseInt(_0x51752f(0x8e)) + parseInt(_0x51752f(0x83)) + parseInt(_0x51752f(0x76)) * -parseInt(_0x51752f(0x79)) + parseInt(_0x51752f(0x95)) * parseInt(_0x51752f(0x91)) + -parseInt(_0x51752f(0x69)) * -parseInt(_0x51752f(0x6a)) + -parseInt(_0x51752f(0x8c)) * parseInt(_0x51752f(0x96));
            if (_0x161ba0 === _0x4878c3)
                break;
            else
                _0x409905['push'](_0x409905['shift']());
        } catch (_0x4f5443) {
            _0x409905['push'](_0x409905['shift']());
        }
    }
}(a49_0x3190, 0xe5935), describe('jasmineUnderTest.util', function () {
    var _0x3b9c88 = a49_0x4d2f;
    describe(_0x3b9c88(0x6d), function () {
        var _0x4e35fc = _0x3b9c88;
        it(_0x4e35fc(0x72), function () {
            var _0x5b41a8 = _0x4e35fc;
            expect(jasmineUnderTest['isArray_']([]))[_0x5b41a8(0x8b)](!![]), expect(jasmineUnderTest['isArray_'](['a']))[_0x5b41a8(0x8b)](!![]);
        }), it(_0x4e35fc(0x8f), function () {
            var _0x4c402a = _0x4e35fc;
            expect(jasmineUnderTest['isArray_'](undefined))[_0x4c402a(0x8b)](![]), expect(jasmineUnderTest[_0x4c402a(0x6d)]({}))[_0x4c402a(0x8b)](![]), expect(jasmineUnderTest['isArray_'](function () {
            }))[_0x4c402a(0x8b)](![]), expect(jasmineUnderTest[_0x4c402a(0x6d)](_0x4c402a(0x82)))[_0x4c402a(0x8b)](![]), expect(jasmineUnderTest[_0x4c402a(0x6d)](0x5))['toBe'](![]), expect(jasmineUnderTest[_0x4c402a(0x6d)](null))[_0x4c402a(0x8b)](![]);
        });
    }), describe('isObject_', function () {
        var _0x373ff4 = _0x3b9c88;
        it(_0x373ff4(0x88), function () {
            var _0x1a7fd8 = _0x373ff4;
            expect(jasmineUnderTest[_0x1a7fd8(0x73)]({}))['toBe'](!![]), expect(jasmineUnderTest[_0x1a7fd8(0x73)]({ 'an': 'object' }))[_0x1a7fd8(0x8b)](!![]);
        }), it(_0x373ff4(0x7b), function () {
            var _0x3e50c1 = _0x373ff4;
            expect(jasmineUnderTest['isObject_'](undefined))['toBe'](![]), expect(jasmineUnderTest[_0x3e50c1(0x73)]([]))[_0x3e50c1(0x8b)](![]), expect(jasmineUnderTest[_0x3e50c1(0x73)](function () {
            }))[_0x3e50c1(0x8b)](![]), expect(jasmineUnderTest[_0x3e50c1(0x73)](_0x3e50c1(0x82)))[_0x3e50c1(0x8b)](![]), expect(jasmineUnderTest[_0x3e50c1(0x73)](0x5))[_0x3e50c1(0x8b)](![]), expect(jasmineUnderTest[_0x3e50c1(0x73)](null))[_0x3e50c1(0x8b)](![]);
        });
    }), describe(_0x3b9c88(0x93), function () {
        var _0xdb44c7 = _0x3b9c88, _0x27878a, _0x42c837, _0x7daa0d = function () {
                this['then'] = function () {
                };
            };
        beforeEach(function () {
            jasmine['getEnv']()['requirePromises'](), _0x27878a = new Promise(function (_0x128922, _0x27854d) {
            }), _0x42c837 = new _0x7daa0d();
        }), describe(_0xdb44c7(0x66), function () {
            var _0x1844b2 = _0xdb44c7;
            it(_0x1844b2(0x80), function () {
                var _0x407f19 = _0x1844b2;
                expect(jasmineUnderTest[_0x407f19(0x66)](_0x27878a))[_0x407f19(0x8b)](!![]);
            }), it(_0x1844b2(0x92), function () {
                var _0x16b3d2 = _0x1844b2;
                expect(jasmineUnderTest[_0x16b3d2(0x66)](_0x42c837))[_0x16b3d2(0x8b)](![]);
            }), it(_0x1844b2(0x67), function () {
                var _0x5a4295 = _0x1844b2;
                expect(jasmineUnderTest[_0x5a4295(0x66)](_0x5a4295(0x89)))[_0x5a4295(0x8b)](![]);
            }), it(_0x1844b2(0x70), function () {
                var _0x546a3d = _0x1844b2;
                expect(jasmineUnderTest[_0x546a3d(0x66)](0x3))['toBe'](![]);
            }), it('should\x20return\x20false\x20for\x20null', function () {
                var _0x17758c = _0x1844b2;
                expect(jasmineUnderTest['isPromise'](null))[_0x17758c(0x8b)](![]);
            }), it(_0x1844b2(0x7c), function () {
                var _0x2eb8f9 = _0x1844b2;
                expect(jasmineUnderTest[_0x2eb8f9(0x66)](undefined))[_0x2eb8f9(0x8b)](![]);
            }), it(_0x1844b2(0x6c), function () {
                var _0x51b8d1 = _0x1844b2;
                expect(jasmineUnderTest[_0x51b8d1(0x66)]([]))[_0x51b8d1(0x8b)](![]);
            }), it(_0x1844b2(0x7a), function () {
                var _0x460dd3 = _0x1844b2;
                expect(jasmineUnderTest[_0x460dd3(0x66)]({}))[_0x460dd3(0x8b)](![]);
            }), it(_0x1844b2(0x74), function () {
                var _0x1b89f6 = _0x1844b2;
                expect(jasmineUnderTest[_0x1b89f6(0x66)](!![]))[_0x1b89f6(0x8b)](![]);
            });
        }), describe('isPromiseLike', function () {
            var _0x4ad511 = _0xdb44c7;
            it(_0x4ad511(0x80), function () {
                var _0x5b748b = _0x4ad511;
                expect(jasmineUnderTest['isPromiseLike'](_0x27878a))[_0x5b748b(0x8b)](!![]);
            }), it(_0x4ad511(0x6b), function () {
                var _0x3c692a = _0x4ad511;
                expect(jasmineUnderTest[_0x3c692a(0x90)](_0x42c837))['toBe'](!![]);
            }), it('should\x20return\x20false\x20if\x20then\x20is\x20not\x20a\x20function', function () {
                var _0x284b5d = _0x4ad511;
                expect(jasmineUnderTest['isPromiseLike']({ 'then': { 'its': _0x284b5d(0x87) } }))[_0x284b5d(0x8b)](![]);
            }), it(_0x4ad511(0x67), function () {
                var _0x14153d = _0x4ad511;
                expect(jasmineUnderTest['isPromiseLike'](_0x14153d(0x89)))[_0x14153d(0x8b)](![]);
            }), it('should\x20return\x20false\x20for\x20numbers', function () {
                var _0x5d1e89 = _0x4ad511;
                expect(jasmineUnderTest['isPromiseLike'](0x3))[_0x5d1e89(0x8b)](![]);
            }), it('should\x20return\x20false\x20for\x20null', function () {
                var _0x34527a = _0x4ad511;
                expect(jasmineUnderTest[_0x34527a(0x90)](null))[_0x34527a(0x8b)](![]);
            }), it(_0x4ad511(0x7c), function () {
                var _0x199992 = _0x4ad511;
                expect(jasmineUnderTest['isPromiseLike'](undefined))[_0x199992(0x8b)](![]);
            }), it(_0x4ad511(0x6c), function () {
                var _0x2a3054 = _0x4ad511;
                expect(jasmineUnderTest[_0x2a3054(0x90)]([]))[_0x2a3054(0x8b)](![]);
            }), it(_0x4ad511(0x7a), function () {
                var _0x4db307 = _0x4ad511;
                expect(jasmineUnderTest[_0x4db307(0x90)]({}))[_0x4db307(0x8b)](![]);
            }), it(_0x4ad511(0x74), function () {
                var _0x283ca7 = _0x4ad511;
                expect(jasmineUnderTest[_0x283ca7(0x90)](!![]))['toBe'](![]);
            });
        });
    }), describe('isUndefined', function () {
        it('reports\x20if\x20a\x20variable\x20is\x20defined', function () {
            var _0x31aa5f = a49_0x4d2f, _0x3b8191;
            expect(jasmineUnderTest['util'][_0x31aa5f(0x71)](_0x3b8191))['toBe'](!![]), expect(jasmineUnderTest[_0x31aa5f(0x7f)][_0x31aa5f(0x71)](_0x6d2c40))['toBe'](!![]);
            var _0x6d2c40 = _0x31aa5f(0x7e);
            expect(jasmineUnderTest[_0x31aa5f(0x7f)]['isUndefined'](_0x6d2c40))[_0x31aa5f(0x8b)](![]);
        });
    }), describe('getPropertyDescriptor', function () {
        var _0x1a036d = _0x3b9c88;
        it(_0x1a036d(0x78), function () {
            var _0x1c36e8 = _0x1a036d, _0xfd0802 = { 'prop': 0x1 }, _0x5e4fdf = jasmineUnderTest[_0x1c36e8(0x7f)][_0x1c36e8(0x8a)](_0xfd0802, _0x1c36e8(0x6e)), _0x1c27ea = Object[_0x1c36e8(0x85)](_0xfd0802, _0x1c36e8(0x6e));
            expect(_0x5e4fdf)[_0x1c36e8(0x7d)](_0x1c27ea);
        }), it(_0x1a036d(0x64), function () {
            var _0x179457 = _0x1a036d, _0x3bcc2b = { 'prop': 0x1 }, _0x148aac = jasmineUnderTest[_0x179457(0x7f)][_0x179457(0x8a)](_0x3bcc2b, 'prop'), _0xe1f93 = Object[_0x179457(0x85)](_0x3bcc2b, _0x179457(0x6e));
            expect(_0x148aac)[_0x179457(0x7d)](_0xe1f93);
        });
    }), describe(_0x3b9c88(0x68), function () {
        var _0x5ce417 = _0x3b9c88;
        it(_0x5ce417(0x94), function () {
            var _0x4ac4bf = _0x5ce417, _0x360f58 = {
                    'foo': 0x3,
                    'bar': 0x4,
                    'baz': 0x5
                }, _0x235f67 = {
                    'bar': 0x6,
                    'quux': 0x7
                };
            expect(jasmineUnderTest[_0x4ac4bf(0x7f)]['objectDifference'](_0x360f58, _0x235f67))[_0x4ac4bf(0x7d)]({
                'foo': 0x3,
                'baz': 0x5
            });
        }), it(_0x5ce417(0x81), function () {
            var _0x274add = _0x5ce417;
            function _0x2f73ee() {
            }
            _0x2f73ee[_0x274add(0x86)]['x'] = 0x1, _0x2f73ee[_0x274add(0x86)]['y'] = 0x2;
            var _0x8b324c = new _0x2f73ee();
            _0x8b324c['x'] = 0x1;
            var _0x353d2d = new _0x2f73ee();
            _0x353d2d['y'] = 0x2, expect(jasmineUnderTest[_0x274add(0x7f)]['objectDifference'](_0x8b324c, _0x353d2d))[_0x274add(0x7d)]({ 'x': 0x1 }), expect(jasmineUnderTest[_0x274add(0x7f)][_0x274add(0x68)](_0x353d2d, _0x8b324c))[_0x274add(0x7d)]({ 'y': 0x2 });
        });
    }), describe(_0x3b9c88(0x84), function () {
        var _0x4b60e5 = _0x3b9c88;
        it(_0x4b60e5(0x77), function () {
            var _0x582616 = _0x4b60e5;
            expect(jasmineUnderTest['util'][_0x582616(0x84)]())[_0x582616(0x6f)](/util.js\/?$/), expect(jasmine['util'][_0x582616(0x84)]())['toMatch'](/jasmine.js\/?$/);
        });
    });
}));